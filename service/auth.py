import base64
import calendar
import datetime
import hashlib
import jwt

from flask import current_app


def __generate_password_digest(password):
    return hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),  # Convert the password to bytes
        salt=current_app.config["PWD_HASH_SALT"],
        iterations=current_app.config["PWD_HASH_ITERATIONS"]
    )


def generate_password_hash(password: str) -> str:
    return base64.b64encode(__generate_password_digest(password)).decode('utf-8')


def compare_passwords(user_password, hashed_password):
    return generate_password_hash(user_password) == hashed_password


def generate_token(username, password_hash, password, is_refreshed=True):
    if username is None:
        return None

    if not is_refreshed:
        if not compare_passwords(password, password_hash):
            return None

    data = {
        'username': username,
        'password': password
    }

    # access_token
    min15 = datetime.datetime.utcnow() + datetime.timedelta(minutes=current_app.config['TOKEN_EXPIRE_MINUTES'])
    data['exp'] = calendar.timegm(min15.timetuple())
    access_token = jwt.encode(data,
                              key=current_app.config['SECRET_KEY'],
                              algorithm=current_app.config['ALGORITHM'])

    # refresh token
    min_day = datetime.datetime.utcnow() + datetime.timedelta(minutes=current_app.config['TOKEN_EXPIRE_DAYS'])
    data['exp'] = calendar.timegm(min_day.timetuple())
    refresh_token = jwt.encode(data, key=current_app.config['SECRET_KEY'], algorithm=current_app.config['ALGORITHM'])

    return {
        'access_token': access_token,
        'refresh_token': refresh_token
    }


def approve_token(token):
    data = jwt.decode(token, key=current_app.config['SECRET_KEY'], algorithms=current_app.config['ALGORITHM'])

    username = data.get('username')
    password = data.get('password')

    return generate_token(username=username, password_hash=None, password=password, is_refreshed=True)
