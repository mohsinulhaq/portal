from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail
from flask_login import LoginManager

# create an instance of Flask
app = Flask(__name__)

# include config from config.py
app.config.from_object('config')

# login
login_manager = LoginManager(app)

# email authentication
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# email sending
mail = Mail(app)

# database connection
db = SQLAlchemy(app)

# to prevent circular import
import portal.views
