import datetime
import shlex
from http import HTTPStatus
from pathlib import Path

import flask
from flask import request, render_template, redirect, url_for
from flask.json import jsonify
from flask_login import login_user, logout_user, login_required, current_user

from app import app, db
from app.attack.convert import split_by_essid, convert_to_22000
from app.attack.worker import HashcatWorker
from app.config import BENCHMARK_UPDATE_PERIOD, BENCHMARK_FILE
from app.domain import TaskInfoStatus
from app.login import LoginForm, RegistrationForm, User, RoleEnum, register_user, create_first_users, Role, \
    roles_required, user_has_roles
from app.uploader import cap_uploads, UploadForm, UploadedTask, check_incomplete_tasks
from app.utils import read_last_benchmark, bssid_essid_from_22000, is_safe_url, wrap_render_template
from app.word_magic import create_digits_wordlist

hashcat_worker = HashcatWorker(app)
render_template = wrap_render_template(render_template)


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
    create_digits_wordlist()
    check_incomplete_tasks()


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        if not user_has_roles(current_user, RoleEnum.USER):
            return flask.abort(403, description="You do not have the permission to start jobs.")
        filename = cap_uploads.save(request.files['capture'], folder=current_user.username)
        cap_path = Path(app.config['CAPTURES_DIR']) / filename
        cap_path = Path(shlex.quote(str(cap_path)))
        file_22000 = convert_to_22000(cap_path)
        folder_split_by_essid = split_by_essid(file_22000)
        tasks = {}
        for file_essid in folder_split_by_essid.iterdir():
            bssid_essid = next(bssid_essid_from_22000(file_essid))
            bssid, essid = bssid_essid.split(':')
            essid = bytes.fromhex(essid).decode('utf-8')
            new_task = UploadedTask(user_id=current_user.id, filename=cap_path.name, wordlist=form.wordlist.data,
                                    rule=form.rule.data, bssid=bssid, essid=essid,
                                    hashcat_args=f"--workload-profile={form.workload.data}")
            tasks[file_essid] = new_task
        db.session.add_all(tasks.values())
        db.session.commit()
        for file_essid, task in tasks.items():
            hashcat_worker.submit_capture(file_essid, uploaded_form=form, task=task)
        flask.flash(f"Uploaded {filename}")
        return redirect(url_for('user_profile'))
    return render_template('upload.html', title='Upload', form=form)


@app.route('/user_profile')
@login_required
def user_profile():
    return render_template('user_profile.html', title='Home', tasks=current_user.uploads[::-1],
                           benchmark=read_last_benchmark())


@app.route('/progress')
@login_required
def progress():
    tasks_progress = []
    user_tasks_id = set(task.id for task in current_user.uploads)
    locks = set(hashcat_worker.locks.values())
    locks.update(hashcat_worker.locks_onetime)
    hashcat_worker.locks_onetime.clear()
    for lock in locks:
        with lock:
            task_id = lock.task_id
            if task_id in user_tasks_id:
                task_progress = dict(task_id=task_id,
                                     progress=f"{lock.progress:.1f}",
                                     status=lock.status,
                                     found_key=lock.found_key)
                tasks_progress.append(task_progress)
    return jsonify(tasks_progress)


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
    # register Guest by User
    # does not make much sense except for the demonstration purpose
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = register_user(user=form.username.data, password=form.password.data, roles=RoleEnum.GUEST)
        flask.flash("You have been successfully registered as {role} '{name}'.".format(role=RoleEnum.GUEST.value,
                                                                                       name=user.username))
        return proceed_login(user)
    return render_template('register.html', title='Sign up', form=form)


@app.route('/register_admin', methods=['GET', 'POST'])
@login_required
@roles_required(RoleEnum.ADMIN)
def register_admin():
    # register User by Admin
    form = RegistrationForm()
    if form.validate_on_submit():
        user = register_user(user=form.username.data, password=form.password.data, roles=RoleEnum.USER)
        flask.flash("You have successfully registered the new {role} '{name}'.".format(role=RoleEnum.USER.value,
                                                                                       name=user.username))
        return redirect(url_for('index'))
    return render_template('register.html', title='Admin register', form=form)


@app.route("/benchmark")
@login_required
def benchmark():
    def start_benchmark():
        hashcat_worker.benchmark()
        return jsonify("Started benchmark.")

    if not BENCHMARK_FILE.exists():
        return start_benchmark()
    since_last_update = datetime.datetime.now() - hashcat_worker.last_benchmark_call
    wait_time = BENCHMARK_UPDATE_PERIOD - since_last_update.seconds
    if wait_time > 0:
        return jsonify("Wait {wait_time} seconds for the next benchmark update.".format(wait_time=wait_time))
    else:
        return start_benchmark()


@app.route("/cancel/<int:task_id>")
@login_required
def cancel(task_id):
    task = UploadedTask.query.get(task_id)
    if task is None:
        return flask.Response(status=HTTPStatus.BAD_REQUEST)
    if task.user_id != current_user.id:
        return flask.Response(status=HTTPStatus.FORBIDDEN)
    if hashcat_worker.cancel(task.id):
        return jsonify(TaskInfoStatus.CANCELLED)
    else:
        # mark it as ABORTED but it may be with a high chance set to CANCELLED later on
        task.status = TaskInfoStatus.ABORTED
        return jsonify("Couldn't cancel the task")


@app.route('/terminate')
@login_required
@roles_required(RoleEnum.ADMIN)
def terminate():
    hashcat_worker.terminate()
    return jsonify("Terminated all jobs")
