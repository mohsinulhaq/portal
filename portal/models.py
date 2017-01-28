from . import db
from werkzeug.security import generate_password_hash
from flask_login import UserMixin


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    uid = db.Column(db.Integer, primary_key=True, nullable=False,
                    autoincrement=True)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password = db.Column(db.String(512), nullable=False)
    verified = db.Column(db.Boolean())

    def __init__(self, email, password, verified=False):
        self.email = email
        self.password = generate_password_hash(password)
        self.verified = verified

    def __repr__(self):
        return '<User %r>' % self.email

    def get_id(self):
        return str(self.uid)
