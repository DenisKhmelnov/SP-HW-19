from dao.model.user import User


class UserDAO:
    def __init__(self, session):
        self.session = session

    def get_one(self, bid):
        return self.session.query(User).get(bid)

    def get_all(self):
        return self.session.query(User).all()

    def get_by_name(self, username):
        try:
            user = self.session.query(User).filter(User.username == username).first()
        except Exception as e:
            self.session.rollback()
            print(e)
            user = None
        return user

    def create(self, new_user):
        ent = User(**new_user)
        self.session.add(ent)
        self.session.commit()

        return ent

    def delete(self, rid):
        user = self.get_one(rid)
        self.session.delete(user)
        self.session.commit()

    def update(self, user_d):
        user = self.get_one(user_d.get("id"))
        user.name = user.get("name")

        self.session.add(user)
        self.session.commit()