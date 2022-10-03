from flask import request
from flask_restx import Resource, Namespace
from service import auth
from implemented import user_service

user_ns = Namespace('auth')


@user_ns.route('/')
class AuthView(Resource):
    def post(self):
        req_json = request.json
        username = req_json.get('username')
        password = req_json.get('password')

        if not username:
            return "Не передано имя пользователя", 401

        user_db = user_service.get_by_name(username=username)

        if user_db:
            return auth.generate_token(password=password,
                                       username=username,
                                       password_hash=user_db.password,
                                       is_refreshed=False
                                       ), 201

        return "", 401

    def put(self):
        req_json = request.json

        if not req_json.get('refresh_token'):
            return "Refresh token не передан", 401

        return auth.approve_token(req_json.get('refresh_token')), 200
