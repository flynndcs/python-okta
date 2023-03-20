from flask_login import UserMixin

# Simulate user database
USERS_DB = {}

class User(UserMixin):

    """Custom User class."""

    def __init__(self, id_, name, email, aoa_id=None):
        self.id = id_
        self.name = name
        self.email = email
        self.aoa_id = aoa_id

    def claims(self):
        """Use this method to render all assigned claims on profile page."""
        return {'name': self.name,
                'email': self.email,
                'aoa_id': self.aoa_id}.items()

    @staticmethod
    def get(user_id):
        return USERS_DB.get(user_id)

    @staticmethod
    def create(user_id, name, email,aoa_id=None):
        USERS_DB[user_id] = User(user_id, name, email,aoa_id)
