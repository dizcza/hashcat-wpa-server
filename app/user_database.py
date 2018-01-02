from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_jwt import JWT
from flask_login import UserMixin
import sqlalchemy.exc
import os

from app.app_logger import logger


def create_jwt(app):
    db = SQLAlchemy(app)

    class User(UserMixin, db.Model):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(64), unique=True, index=True)
        password_hash = db.Column(db.String(128))

        def set_password(self, password):
            self.password_hash = generate_password_hash(password)

        def verify_password(self, password):
            return check_password_hash(self.password_hash, password)

        def generate_auth_token(self, expires_in=3600):
            s = Serializer(app.config['SECRET_KEY'], expires_in=expires_in)
            return s.dumps({'id': self.id}).decode('utf-8')

        @staticmethod
        def verify_auth_token(token):
            s = Serializer(app.config['SECRET_KEY'])
            try:
                data = s.loads(token)
            except:
                return None
            return User.query.get(data['id'])

    def verify(username, password):
        if not (username and password):
            return False
        user = User.query.filter_by(username=username).first()
        if user is None:
            return False
        if user.verify_password(password):
            return user
        return False

    def identity(payload):
        user_id = payload['identity']
        return {"user_id": user_id}

    try:
        # does table exist?
        User.query.filter_by(username="definitely_nonexistent_user").first()
    except sqlalchemy.exc.OperationalError:
        db.create_all()

    username = os.environ['HASHCAT_USERNAME']
    if username == '':
        username = "test"
    user = User.query.filter_by(username=username).first()
    if user is None:
        user = User(username=username)
        password = os.environ['HASHCAT_PASSWORD']
        if password == '':
            password = "test"
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        logger.info("Created a new user '{}'".format(username))

    jwt = JWT(app, verify, identity)
    return jwt
