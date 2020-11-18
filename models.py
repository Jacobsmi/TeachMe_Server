from enum import unique
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify
from config import app
import sys

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)

    def __init__(self, email, password) ->  None:
        self.email = email
        self.password = password

class Class(db.Model):
    __tablename__ = 'classes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    name = db.Column(db.Text, nullable=False)

    def __init__(self, name, description) ->  None:
        self.name = name
        self.description = description

if __name__ == "__main__":
    db.init_app(app)
    if len(sys.argv) > 1:
        if sys.argv[1].lower() == 'migrate' or sys.argv[1].lower() == 'm':
            with app.app_context():
                db.create_all()
        elif sys.argv[1].lower == 'demigrate' or sys.argv[1].lower() == 'd':
            with app.app_context():
                db.drop_all()