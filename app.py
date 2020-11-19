from os import access
from flask import Flask, request
from flask.json import jsonify
from flask_jwt_extended.utils import get_csrf_token
from config import app
from models import db, User
import sys
from sqlalchemy import exc
import bcrypt
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    create_refresh_token, get_jwt_identity, jwt_refresh_token_required,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies
)

''' CURRENT API ROUTES
    - /GetUserInfo
    - /refresh
    - /CreateUser
    - /Login
'''


db.init_app(app)
jwt = JWTManager(app)

@app.route('/')
def home():
    return jsonify(working=True), 200

@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    # Create the new access token
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)

    # Set the access JWT and CSRF double submit protection cookies
    # in this response
    resp = jsonify({'refresh': True})
    set_access_cookies(resp, access_token)
    return resp, 200


'''GET USER INFO ROUTE AND FUNCTIONS'''
@app.route('/GetUserInfo')
@jwt_required
def get_user_info():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


'''CREATE USER FUNCTIONS AND ROUTE'''


def create_user_data(email, password):
    # Hash the plaintext password and prepare for storage in DB
    password = password.encode('utf-8')
    pass_hash = bcrypt.hashpw(password, bcrypt.gensalt())
    pass_hash_decoded = pass_hash.decode('utf8')
    print("User created")
    new_user = User(email, pass_hash_decoded)
    print("Attempting to add to DB")
    db.session.add(new_user)

@app.route('/CreateUser', methods=["POST"])
def create_user():
    try:
        create_user_data(
            request.json['email'], request.json['password']
        )
        print("Created the user")
        # Add the current user to the database
        db.session.commit()
        # Get a JWT access token
        access_token =create_access_token(identity=request.json['email'])
        refresh_token = create_refresh_token(identity=request.json['email'])
        resp = jsonify(create='true')
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        return resp

    # Catch Integrity Error which signals non-unique error
    except exc.IntegrityError as e:
        return jsonify(error='E-Mail is not unique')

    except Exception as e:
        print("UNDEFINED EXCEPTION", e)
        return jsonify(error='Undefined Error')


''' LOGIN FUNCTIONS AND ROUTE'''

def check_password_match(user_password, db_password):
    user_password = user_password.encode('utf-8')
    db_password = db_password.encode('utf-8')
    return bcrypt.checkpw(user_password, db_password)


@app.route('/Login', methods=['POST'])
def login():
    try:
        user = db.session.query(User).filter(User.email == request.json['email']).first()
        password_correct = check_password_match(request.json['password'], user.password)
        if password_correct:
            access_token = create_access_token(identity=request.json['email'])
            refresh_token = create_refresh_token(identity=request.json['email'])
            
            resp = jsonify({'login': True})
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            return resp, 200

        elif not password_correct:
            return jsonify(error='Password is incorrect')
    except AttributeError as e:
        return jsonify(error='There is no account with that email.\nPlease sign up.')
    except:
        return jsonify(error='Undefined Error')

@app.route('/logout', methods=['POST'])
def logout():
    resp = jsonify({'logout': True})
    unset_jwt_cookies(resp)
    return resp, 200

if __name__ == '__main__':
    app.run()