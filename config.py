import os

import pytz


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'instance', 'chat.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 587
    SMTP_EMAIL = os.getenv('SMTP_EMAIL', 'hayyieap060304@gmail.com')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'hgwu tqjj jfyw malg')
    TIMEZONE = pytz.timezone('Asia/Ho_Chi_Minh')  # Định nghĩa múi giờ
