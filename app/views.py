import multiprocessing
import os
import glob
from typing import Optional

from flask import request, abort
from flask.json import jsonify
from flask_jwt import jwt_required, JWTError
from werkzeug.utils import secure_filename

from app import app
from app.user_database import create_jwt
from app.worker import HashcatWorker
from app.slack_sender import SlackSender
from app.app_logger import logger
from app.hashcat_cmd import Rule, WordList
from app.domain import UploadForm

hashcat_worker = HashcatWorker(app)
jwt = create_jwt(app)
hashcat_worker.benchmark(notify=False)


@app.route('/')
def index():
    return jsonify("Welcome to Hashcat WPA/WPA2 server")


def get_rule_header() -> Rule:
    rule = request.headers['rule']
    if rule == "No rule":
        rule = None
    else:
        rule = Rule(rule)
    return rule


def parse_upload_form() -> Optional[UploadForm]:
    """
    :return: UploadForm instance if request is valid, None otherwise
    :raises ValueError, KeyError, IOError
    """
    capture_filepath = secure_filename(request.headers['filename'])
    if os.path.splitext(capture_filepath)[1] != '.cap':
        return None
    capture_filepath = os.path.join(app.config.get("CAPTURES_DIR", ''), capture_filepath)
    timeout = int(request.headers['timeout']) * 60
    wordlist = WordList(request.headers['wordlist'])
    rule = get_rule_header()
    mime_correct = app.config.get('CAPTURE_MIME', '')
    if mime_correct == '':
        logger.warning("For extra security, set correct 'CAPTURE_MIME' env")
    capture_bytes = request.get_data()
    mime_received = capture_bytes[: min(len(capture_bytes), len(mime_correct))]
    if mime_received != mime_correct:
        return None
    with open(capture_filepath, 'wb') as f:
        bytes_written = f.write(capture_bytes)
    if bytes_written != len(capture_bytes):
        raise IOError()
    return UploadForm(capture_filepath, wordlist, rule, timeout)


def log_request():
    str_info = str(request.headers)
    for key in ('REMOTE_ADDR',):
        value = request.environ.get(key)
        str_info += "{}: {}\r\n".format(key, value)
    logger.debug(str_info)


@app.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    log_request()
    try:
        upload_form = parse_upload_form()
    except ValueError or KeyError:
        upload_form = None
    except IOError:
        return abort(400, "Couldn't write received file")
    if upload_form is None:
        return abort(400, "Invalid form")
    hashcat_worker.crack_capture(upload_form)
    capture_filename = os.path.basename(upload_form.capture_path)
    return jsonify("Started processing {}".format(capture_filename))


@app.route("/ping")
@jwt_required()
def ping():
    return "Authorized"


@app.route("/benchmark")
@jwt_required()
def hashcat_benchmark():
    hashcat_worker.benchmark(notify=True)
    return jsonify("See '#benchmark' slack channel")


@app.route("/auth", methods=['POST'])
def auth():
    data = request.get_data()
    if not data:
        raise JWTError('Invalid auth request', "Empty request")
    data = data.decode('ascii')
    parts = data.split(':')
    if len(parts) != 2:
        raise JWTError('Bad Request', 'Invalid credentials')
    username, password = parts
    identity = jwt.authentication_callback(username, password)
    if not identity:
        raise JWTError('Bad Request', 'Invalid credentials')
    access_token = jwt.jwt_encode_callback(identity)
    return jwt.auth_response_callback(access_token, identity)


@app.route("/terminate")
@jwt_required()
def terminate_workers():
    hashcat_worker.terminate()
    return jsonify("Terminated")


@app.route("/list")
@jwt_required()
def list_keys():
    sender = SlackSender()
    sender.list_cracked()
    return jsonify("See #general")
