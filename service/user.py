from dao.user import UserDAO
from service import auth


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, bid):
        return self.dao.get_one(bid)

    def get_all(self):
        return self.dao.get_all()

    def get_by_name(self, username):
        return self.dao.get_by_name(username)

    def create(self, user_d):
        user_d["password"] = auth.generate_password_hash(user_d["password"])
        return self.dao.create(user_d)

    def update(self, user_d):
        self.dao.update(user_d)
        return self.dao

    def delete(self, rid):
        self.dao.delete(rid)
