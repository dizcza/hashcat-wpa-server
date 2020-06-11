import datetime
from pathlib import Path

from flask_uploads import UploadSet, configure_uploads
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import RadioField, IntegerField, SubmitField
from wtforms.validators import DataRequired

from app import app, db
from app.domain import WordList, Rule, NONE_ENUM, TaskInfoStatus, Workload, \
    HashcatMode
from app.utils import read_plain_key

TIMEOUT_HASHCAT_MINUTES = 120


def _wordlist_choices():
    # return a pairs of (id-value, display: str)
    choices = [(NONE_ENUM, "(fast)")]
    choices.extend((wordlist.value, wordlist.value) for wordlist in (
        WordList.ROCKYOU, WordList.PHPBB, WordList.TOP304K))
    return choices


def check_incomplete_tasks():
    for task in UploadedTask.query.filter_by(completed=False):
        key_path = Path(task.filepath).with_suffix('.key')
        if key_path.exists():
            task.found_key = read_plain_key(key_path)
            task.status = TaskInfoStatus.COMPETED
        else:
            task.status = TaskInfoStatus.ABORTED
            task.completed = True
    db.session.commit()


class UploadedTask(db.Model):
    __tablename__ = "uploads"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    filepath = db.Column(db.String(128))
    wordlist = db.Column(db.String(128))
    rule = db.Column(db.String(128))
    workload = db.Column(db.Integer)
    uploaded_time = db.Column(db.DateTime, index=True, default=datetime.datetime.now)
    duration = db.Column(db.Interval, default=datetime.timedelta)
    status = db.Column(db.String(256), default=TaskInfoStatus.SCHEDULED)
    progress = db.Column(db.Float, default=0)
    found_key = db.Column(db.String(256))
    completed = db.Column(db.Boolean, default=False)
    essid = db.Column(db.String(64))
    bssid = db.Column(db.String(64))


class UploadForm(FlaskForm):
    wordlist = RadioField('Wordlist', choices=_wordlist_choices(), default=NONE_ENUM)
    rule = RadioField('Rule', choices=((NONE_ENUM, "(None)"), (Rule.BEST_64.value, Rule.BEST_64.value)),
                      default=NONE_ENUM)
    timeout = IntegerField('Timeout (minutes)', validators=[DataRequired()], default=TIMEOUT_HASHCAT_MINUTES)
    capture = FileField('Capture', validators=[FileRequired(), FileAllowed(HashcatMode.valid_suffixes(),
                                                                           message='Airodump & Hashcat capture files only')])
    workload = RadioField("Workload", choices=tuple((wl.value, wl.name) for wl in Workload),
                          default=Workload.Default.value)
    submit = SubmitField('Submit')


cap_uploads = UploadSet(name='files', extensions=HashcatMode.valid_suffixes(), default_dest=lambda app: app.config['CAPTURES_DIR'])
configure_uploads(app, cap_uploads)
