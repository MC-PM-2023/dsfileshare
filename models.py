from extensions import db
# from flask_sqlalchemy import SQLAlchemy
# db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'desktop_userstable'  # Ensure table name matches your database

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

