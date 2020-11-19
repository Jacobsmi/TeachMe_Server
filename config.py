from flask import Flask
from dotenv import load_dotenv
from flask_cors import CORS
from datetime import time, timedelta
import os

load_dotenv()

app = Flask(__name__)

CORS(app, supports_credentials=True)
# put database credentials in the app's constant
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = os.getenv('JWT_KEY')
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_IN_COOKIES'] = True