from datetime import datetime
from flask_login import UserMixin
from igame.src import bcrypt, db


class User(UserMixin, db.Model):
    __tablename__ = "user_details"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(50), nullable=False)
    user_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    birth_date = db.Column(db.DateTime, nullable=False)
    zip_code = db.Column(db.Integer, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    user_password = db.Column(db.String(40), nullable=False)

    def __init__(self, name: str, username: str, email: str, bday: datetime,
                 zipcode: int, phone: str, password: str):
        self.full_name = name
        self.user_name = username
        self.email = email
        self.birth_date = bday
        self.zip_code = zipcode
        self.phone_number = phone
        self.user_password = bcrypt.generate_password_hash(password)

    def __repr__(self):
        return f'<email {self.email}'