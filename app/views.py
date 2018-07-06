import os
from typing import Optional

import flask
from flask import request, abort, render_template, redirect, url_for
from flask.json import jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename

from app import app
from app.app_logger import logger
from app.domain import UploadForm
from app.hashcat_cmd import Rule, WordList
from app.login import LoginForm, RegistrationForm
from app.login import User, add_new_user
from app.slack_sender import SlackSender
from app.utils import is_safe_url, log_request
from app.worker import HashcatWorker

hashcat_worker = HashcatWorker(app)


@app.route('/')
@app.route('/index')
def index():
    return render_template('base.html')


def get_rule_header() -> Rule:
    rule = request.headers['rule']
    if rule == "(None)":
        rule = None
    else:
        rule = Rule(rule)
    return rule


def get_wordlist_header() -> WordList:
    wordlist = request.headers['wordlist']
    if wordlist == "(None)":
        wordlist = None
    else:
        wordlist = WordList(wordlist)
    return wordlist


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
    wordlist = get_wordlist_header()
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


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    log_request(logger)
    try:
        upload_form = parse_upload_form()
    except ValueError or KeyError:
        upload_form = None
    except IOError:
        return abort(400, "Couldn't write received file")
    if upload_form is None:
        return abort(400, "Invalid form")
    job_id = hashcat_worker.crack_capture(upload_form)
    capture_filename = os.path.basename(upload_form.capture_path)
    return jsonify(message="Started processing {}".format(capture_filename),
                   job_id=job_id)


@app.route('/secret')
@login_required
def secret():
    return jsonify('Secret page!')


@app.route('/progress/<int:job_id>')
@login_required
def progress(job_id):
    lock = hashcat_worker.locks[job_id]
    with lock:
        response = jsonify(progress=lock.progress,
                           status=lock.status,
                           key=lock.key,
                           completed=lock.completed)
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data):
            flask.flash('Invalid username or password', category='error')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not is_safe_url(next_page):
            return flask.abort(400)
        flask.flash('Successfully logged in.')
        return redirect(next_page or flask.url_for('index'))
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        add_new_user(form)
        flask.flash('You have been successfully registered.')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/benchmark")
@login_required
def hashcat_benchmark():
    hashcat_worker.benchmark()
    return jsonify("See #benchmark")


@app.route("/terminate")
@login_required
def terminate_workers():
    hashcat_worker.terminate()
    return jsonify("Terminated")


@app.route("/list")
@login_required
def list_keys():
    sender = SlackSender()
    sender.list_cracked()
    return jsonify("See #general")
