import datetime
import os

import flask
from flask import request, render_template, redirect, url_for
from flask.json import jsonify
from flask_login import login_user, logout_user, login_required, current_user

from app import app, db
from app.login import LoginForm, RegistrationForm
from app.login import User, RoleEnum, register_user, create_first_users, Role, roles_required, user_has_roles
from app.uploader import cap_uploads, UploadForm, UploadedTask, check_incomplete_tasks
from app.utils import is_safe_url, str_to_date, is_mime_valid, read_last_benchmark
from app.worker import HashcatWorker

hashcat_worker = HashcatWorker(app)


def proceed_login(user: User, remember=False):
    login_user(user, remember=remember)
    next_page = request.args.get('next')
    if not is_safe_url(next_page):
        return flask.abort(400)
    flask.flash('Successfully logged in.')
    return redirect(next_page or flask.url_for('index'))


@app.route('/')
@app.route('/index')
def index():
    return render_template('base.html')


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role, UploadedTask=UploadedTask)


@app.before_first_request
def before_first_request():
    create_first_users()
    check_incomplete_tasks()


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        if not user_has_roles(current_user, RoleEnum.USER):
            return flask.abort(403, description="You do not have the permission to start jobs.")
        filename = cap_uploads.save(request.files['capture'], folder=current_user.username)
        filepath = os.path.join(app.config['CAPTURES_DIR'], filename)
        if is_mime_valid(filepath):
            new_task = UploadedTask(user_id=current_user.id, filepath=filepath, wordlist=form.wordlist.data,
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
    return render_template('user_profile.html', title='Home', tasks=current_user.uploads[::-1],
                           benchmark=read_last_benchmark(), enumerate=enumerate, basename=os.path.basename)


@app.route('/progress')
@login_required
def progress():
    tasks_progress = []
    user_tasks_id = set(task.id for task in current_user.uploads)
    user_tasks_running_id = set(hashcat_worker.locks.keys()).intersection(user_tasks_id)
    for task_id in user_tasks_running_id:
        job_id, lock = hashcat_worker.locks[task_id]
        with lock:
            task_progress = dict(task_id=task_id,
                                 progress="{:.1f}".format(lock.progress),
                                 status=lock.status,
                                 found_key=lock.key,
                                 completed=lock.completed)
        tasks_progress.append(task_progress)
    return jsonify(tasks_progress)


@app.route('/delete_lock/<int:task_id>')
@login_required
def delete_lock(task_id):
    if task_id in hashcat_worker.locks:
        del hashcat_worker.locks[task_id]


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
        return proceed_login(user, remember=form.remember_me.data)
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
        user = register_user(form, RoleEnum.GUEST)
        flask.flash("You have been successfully registered as {role} '{name}'.".format(role=RoleEnum.GUEST.value,
                                                                                       name=user.username))
        return proceed_login(user)
    return render_template('register.html', title='Register', form=form)


@app.route('/register_admin', methods=['GET', 'POST'])
@login_required
@roles_required(RoleEnum.ADMIN)
def register_admin():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = register_user(form, RoleEnum.USER)
        flask.flash("You have successfully registered the new {role} '{name}'.".format(role=RoleEnum.USER.value,
                                                                                       name=user.username))
        return redirect(url_for('index'))
    return render_template('register.html', title='Register', form=form)


@app.route("/benchmark")
@login_required
def benchmark():
    benchmark_last = read_last_benchmark()
    since_last_update = datetime.datetime.now() - str_to_date(benchmark_last.date)
    wait_time = app.config['BENCHMARK_UPDATE_PERIOD'] - since_last_update.seconds
    if benchmark_last.speed == 0 or wait_time < 0:
        hashcat_worker.benchmark()
        return jsonify("Started benchmark.")
    else:
        message = "Wait {wait_time} seconds for the next benchmark update.".format(wait_time=wait_time)
        return jsonify(message)


@app.route("/terminate")
@login_required
def terminate_workers():
    hashcat_worker.terminate()
    return jsonify("Terminated")
