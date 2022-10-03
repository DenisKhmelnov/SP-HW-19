import jwt
from flask import request, current_app

from implemented import user_service
from service.auth import generate_token


def auth_required(func):
    def wrapper(*args, **kwargs):
        token = request.headers.environ.get('AUTH_AUTHORIZATION').replace('Bearer', '')

        if not token:
            return "Вы не передали токен в хедере"

        try:
            data = jwt.decode(token,
                              key=current_app.config['SECRET_KEY'],
                              algorithms=current_app.config['ALGORITHM'])

            return func(*args, **kwargs)
        except Exception as e:
            print(e)

    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        token = request.headers.environ.get('AUTH_AUTHORIZATION').replace('Bearer', '')

        if not token:
            return "Вы не передали токен в хедере"

        try:
            data = jwt.decode(token,
                              key=current_app.config['SECRET_KEY'],
                              algorithms=current_app.config['ALGORITHM'])

            user = user_service.get_by_name(data.get('username'))
            if user:
                if not user.role == 'admin':
                    return "У вас нет админских прав", 401

            return func(*args, **kwargs)
        except Exception as e:
            print(e)

    return wrapper
