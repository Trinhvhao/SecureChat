from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
import os
from config import Config
from datetime import datetime
import sqlite3

# Khởi tạo Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Đảm bảo SECRET_KEY được đặt
if not app.config.get('SECRET_KEY'):
    app.config['SECRET_KEY'] = os.urandom(24)
else:
    app.config['SECRET_KEY'] = Config.SECRET_KEY

# Cấu hình session
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session hết hạn sau 30 phút

# Sử dụng TIMEZONE từ config
vn_timezone = Config.TIMEZONE

# Cấu hình SQLAlchemy với múi giờ
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {'check_same_thread': False},
    'pool_pre_ping': True,
    'pool_size': 5,
    'max_overflow': 10
}

# Khởi tạo SQLAlchemy
db = SQLAlchemy()

# Tùy chỉnh model base để áp dụng múi giờ
class BaseModel(db.Model):
    __abstract__ = True
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(vn_timezone))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(vn_timezone), onupdate=lambda: datetime.now(vn_timezone))

# Gắn db với app
db.init_app(app)

# Import models sau khi khởi tạo db
from models import User, Invitation, Message, Contact, Session

# Import và đăng ký blueprint
from routes import bp
app.register_blueprint(bp)

# Tạo bảng cơ sở dữ liệu nếu chưa tồn tại
with app.app_context():
    db_path = os.path.join(os.path.dirname(__file__), 'instance', 'chat.db')
    if not os.path.exists(db_path):
        db.create_all()
    else:
        # Kiểm tra xem cơ sở dữ liệu có bảng hay không
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        conn.close()
        if not tables:  # Nếu không có bảng nào, tạo mới
            db.create_all()

if __name__ == '__main__':
    app.run(debug=True)