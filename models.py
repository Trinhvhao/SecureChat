import os
from datetime import datetime

import pytz

from app import db, vn_timezone


# class Config:
#     SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')
#     SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'instance', 'chat.db')
#     SQLALCHEMY_TRACK_MODIFICATIONS = False
#     SMTP_SERVER = 'smtp.gmail.com'
#     SMTP_PORT = 587
#     SMTP_EMAIL = os.getenv('SMTP_EMAIL', 'hayyieap060304@gmail.com')
#     SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'hgwu tqjj jfyw malg')
#     TIMEZONE = pytz.timezone('Asia/Ho_Chi_Minh')  # Định nghĩa múi giờ


class BaseModel(db.Model):
    __abstract__ = True
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(vn_timezone))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(vn_timezone),
                           onupdate=lambda: datetime.now(vn_timezone))


class User(BaseModel):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    gmail = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    rsa_public_key = db.Column(db.Text, nullable=False)
    rsa_private_key = db.Column(db.Text, nullable=False)
    is_online = db.Column(db.Boolean, default=False)  # Thêm cột trạng thái online


class Invitation(BaseModel):
    __tablename__ = 'invitations'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_gmail = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    status = db.Column(db.String(20), default='pending')
    sent_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(vn_timezone))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)  # Added expires_at column


class Contact(BaseModel):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    contact_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    added_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(vn_timezone))
    user = db.relationship('User', foreign_keys=[contact_user_id], backref='contacts')


class Message(BaseModel):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    iv = db.Column(db.Text, nullable=False)
    hash = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(vn_timezone))
    status = db.Column(db.String(20), default='sent')


class Session(BaseModel):
    __tablename__ = 'sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    contact_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    triple_des_key = db.Column(db.Text, nullable=True)


# Thêm mô hình DeleteRequest
class DeleteRequest(BaseModel):
    __tablename__ = 'delete_requests'
    id = db.Column(db.Integer, primary_key=True)
    initiator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    confirmed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    initiator = db.relationship('User', foreign_keys=[initiator_id])
    target = db.relationship('User', foreign_keys=[target_id])
