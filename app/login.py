import os
import warnings
from enum import Enum, unique
from functools import wraps
from typing import Iterable, Union

import flask
from flask_login import LoginManager, UserMixin, current_user
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import ValidationError, DataRequired, EqualTo

from app import app, db
from app.app_logger import logger


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')


login_manager = LoginManager(app)
login_manager.login_view = 'login'


@unique
class RoleEnum(Enum):
    ADMIN = 'Admin'  # can register new people
    USER = 'User'    # can submit tasks
    GUEST = 'Guest'  # anonymous


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.Enum(RoleEnum), unique=True)

    @staticmethod
    def by_enum(role_enum: RoleEnum):
        return Role.query.filter_by(name=role_enum).first()

    def __repr__(self):
        return "<Role {}>".format(self.name.value)


class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    uploads = db.relationship('UploadedTask', lazy=True)
    roles = db.relationship('Role', secondary='user_roles')

    @staticmethod
    def validate_username(username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id: int):
    return User.query.get(user_id)


def register_user(user: str, password: str, roles: Union[RoleEnum, Iterable[RoleEnum]]):
    user = User(username=user)
    user.set_password(password)
    if isinstance(roles, RoleEnum):
        roles = [roles]
    for role_enum in roles:
        user.roles.append(Role.by_enum(role_enum))
    db.session.add(user)
    db.session.commit()
    logger.info(f"Registered {user} user.")
    return user


def create_first_users():
    db.create_all()
    if len(Role.query.all()) == 0:
        for role_enum in RoleEnum:
            db.session.add(Role(name=role_enum))
        db.session.commit()
    if not User.query.filter(User.username == 'guest').first():
        # no 'guest' user yet
        register_user(user='guest', password='gust', roles=RoleEnum.GUEST)

    admin_cred_env_keys = ('HASHCAT_ADMIN_USER', 'HASHCAT_ADMIN_PASSWORD')
    for key in admin_cred_env_keys:
        if key not in os.environ:
            raise KeyError(f"Please set '{key}' environment.")
    admin_name = os.environ['HASHCAT_ADMIN_USER']
    if not User.query.filter(User.username == admin_name).first():
        # no 'admin' user yet
        warnings.warn("It appears that you're running hashcat-wpa-server for the first time. Please run in a terminal "
                      "the following commands to mitigate database migration in the future:"
                      "\n flask db init"
                      "\n flask db migrate"
                      "\n flask db upgrade")
        register_user(user=admin_name, password=os.environ['HASHCAT_ADMIN_PASSWORD'],
                      roles=(RoleEnum.ADMIN, RoleEnum.USER))


def user_has_roles(user: User, *requirements: RoleEnum) -> bool:
    """ Return True if the user has all of the specified roles. Return False otherwise.
        For example:
            has_roles(user1, 'a', 'b')
        Translates to:
            user1 has roles 'a' AND 'b'
    """
    if not user.is_authenticated:
        return False
    user_roles = set(role.name for role in user.roles)
    return set(requirements).issubset(user_roles)


def roles_required(*requirements: RoleEnum):
    """| This decorator ensures that the current user is authenticated,
    | and has *all* of the specified roles (AND operation).
    | Calls abort(403) when the user is not authenticated
        or when the user does not have the required roles.
    | Calls the decorated view otherwise.
    """
    def wrapper(view_function):

        @wraps(view_function)    # Tells debuggers that is is a function wrapper
        def decorator(*args, **kwargs):
            # User must have the required roles
            if not user_has_roles(current_user, *requirements):
                # Redirect to the unauthorized page
                return flask.abort(403, description="You do not have the permissions.")

            # It's OK to call the view
            return view_function(*args, **kwargs)

        return decorator

    return wrapper
