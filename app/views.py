import os

import flask
from flask import request, render_template, redirect, url_for
from flask.json import jsonify
from flask_login import login_user, logout_user, login_required, current_user

from app import app, db
from app.app_logger import logger
from app.login import LoginForm, RegistrationForm
from app.login import User, add_new_user
from app.uploader import cap_uploads, UploadForm, UploadedTask
from app.utils import is_safe_url, log_request
from app.worker import HashcatWorker

hashcat_worker = HashcatWorker(app)


@app.route('/')
@app.route('/index')
def index():
    return render_template('base.html')


def is_mime_valid(file_path):
    if not os.path.exists(file_path):
        return False
    with open(file_path, 'rb') as f:
        data = f.read()
    return data.startswith(app.config['CAPTURE_MIME'])


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    log_request(logger)
    form = UploadForm()
    if form.validate_on_submit():
        filename = cap_uploads.save(request.files['capture'])
        filepath = os.path.join(app.config['CAPTURES_DIR'], filename)
        if is_mime_valid(filepath):
            new_task = UploadedTask(user_id=current_user.id, filename=filepath, wordlist=form.wordlist.data,
                                    rule=form.rule.data)
            db.session.add(new_task)
            db.session.commit()
            flask.flash("Uploaded {}".format(filename))
            hashcat_worker.crack_capture(new_task, timeout=form.timeout.data)
            return redirect(url_for('user_profile'))
        else:
            flask.flash("Invalid file", category='error')
            return redirect(url_for('upload'))
    return render_template('upload.html', title='Upload', form=form)


@app.route('/user_profile')
@login_required
def user_profile():
    tasks = UploadedTask.query.filter_by(user_id=current_user.id).all()
    return render_template('user_profile.html', title='Home', tasks=tasks)


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
