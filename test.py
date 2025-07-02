import logging
import sqlite3
from datetime import datetime
import pytz
from utils import (
    generate_rsa_key_pair,
    handshake_initiate,
    handshake_respond,
    encrypt_3des_key,
    decrypt_3des_key,
    sign_auth_info,
    verify_auth_info,
    generate_3des_key,
    create_message_packet,
    verify_and_decrypt_message
)

# Cấu hình logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Đặt múi giờ Việt Nam
vn_timezone = pytz.timezone('Asia/Ho_Chi_Minh')


def get_db_connection():
    """Tạo kết nối đến database"""
    conn = sqlite3.connect('instance/chat.db')
    conn.row_factory = sqlite3.Row
    return conn


def setup_db():
    """Khởi tạo database và các bảng"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Tạo các bảng
    tables = [
        '''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            name TEXT, 
            gmail TEXT UNIQUE, 
            password_hash TEXT, 
            rsa_public_key TEXT, 
            rsa_private_key TEXT, 
            created_at TIMESTAMP)''',
        '''CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            sender_id INTEGER, 
            receiver_gmail TEXT, 
            token TEXT, 
            status TEXT, 
            created_at TIMESTAMP)''',
        '''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            sender_id INTEGER, 
            receiver_id INTEGER, 
            ciphertext TEXT, 
            iv TEXT, 
            hash TEXT, 
            signature TEXT, 
            status TEXT, 
            created_at TIMESTAMP)''',
        '''CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER, 
            contact_user_id INTEGER, 
            created_at TIMESTAMP)''',
        '''CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER, 
            contact_user_id INTEGER, 
            triple_des_key TEXT, 
            created_at TIMESTAMP)'''
    ]

    for table in tables:
        cursor.execute(table)

    conn.commit()
    conn.close()
    logger.info("Database initialized")


def register_user(name, gmail, password):
    """Đăng ký user mới"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        public_key, private_key = generate_rsa_key_pair()
        created_at = datetime.now(vn_timezone)
        cursor.execute(
            "INSERT INTO users (name, gmail, password_hash, rsa_public_key, rsa_private_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name, gmail, password, public_key, private_key, created_at)
        )
        conn.commit()
        user_id = cursor.lastrowid
        logger.info(f"User {name} registered successfully (ID: {user_id})")
        return user_id, public_key, private_key
    except Exception as e:
        conn.rollback()
        logger.error(f"Registration failed: {str(e)}")
        raise
    finally:
        conn.close()


def login_user(gmail, password):
    """Đăng nhập user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id, password_hash, rsa_public_key, rsa_private_key FROM users WHERE gmail = ?",
            (gmail,)
        )
        user = cursor.fetchone()
        if user and password == user['password_hash']:
            logger.info(f"User {gmail} logged in successfully")
            return user['id'], user['rsa_public_key'], user['rsa_private_key']
        logger.warning(f"Login failed for {gmail}")
        return None, None, None
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise
    finally:
        conn.close()


def send_invitation(sender_id, receiver_gmail):
    """Gửi lời mời kết bạn"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        token = "dummy_token"
        created_at = datetime.now(vn_timezone)
        cursor.execute(
            "INSERT INTO invitations (sender_id, receiver_gmail, token, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (sender_id, receiver_gmail, token, 'pending', created_at)
        )
        conn.commit()
        logger.info(f"Invitation sent from {sender_id} to {receiver_gmail}")
        return token
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to send invitation: {str(e)}")
        raise
    finally:
        conn.close()


def confirm_invitation(token):
    """Xác nhận lời mời"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT sender_id, receiver_gmail FROM invitations WHERE token = ? AND status = 'pending'",
            (token,)
        )
        invitation = cursor.fetchone()

        if invitation:
            cursor.execute(
                "SELECT id FROM users WHERE gmail = ?",
                (invitation['receiver_gmail'],)
            )
            receiver = cursor.fetchone()

            if receiver:
                created_at = datetime.now(vn_timezone)
                # Cập nhật trạng thái lời mời
                cursor.execute(
                    "UPDATE invitations SET status = 'accepted' WHERE token = ?",
                    (token,)
                )
                # Tạo liên hệ hai chiều
                cursor.execute(
                    "INSERT INTO contacts (user_id, contact_user_id, created_at) VALUES (?, ?, ?)",
                    (invitation['sender_id'], receiver['id'], created_at)
                )
                cursor.execute(
                    "INSERT INTO contacts (user_id, contact_user_id, created_at) VALUES (?, ?, ?)",
                    (receiver['id'], invitation['sender_id'], created_at)
                )
                conn.commit()
                logger.info(f"Invitation confirmed (Token: {token})")
                return True
        return False
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to confirm invitation: {str(e)}")
        raise
    finally:
        conn.close()


def handshake(sender_id, receiver_id):
    """Thực hiện handshake"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Gửi "Hello!" và nhận "Ready!"
        if handshake_initiate() == "Hello!" and handshake_respond() == "Ready!":
            created_at = datetime.now(vn_timezone)
            # Tạo session hai chiều
            cursor.execute(
                "INSERT INTO sessions (user_id, contact_user_id, created_at) VALUES (?, ?, ?)",
                (sender_id, receiver_id, created_at)
            )
            cursor.execute(
                "INSERT INTO sessions (user_id, contact_user_id, created_at) VALUES (?, ?, ?)",
                (receiver_id, sender_id, created_at)
            )
            conn.commit()
            session_id = cursor.lastrowid
            logger.info(f"Handshake completed (Session ID: {session_id})")
            return session_id
        return None
    except Exception as e:
        conn.rollback()
        logger.error(f"Handshake failed: {str(e)}")
        raise
    finally:
        conn.close()


def exchange_key(sender_id, receiver_id, sender_private_key, sender_public_key, receiver_public_key):
    """Trao đổi khóa mã hóa"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Tạo và ký thông tin xác thực
        auth_result = sign_auth_info(sender_id, receiver_id, sender_private_key)

        # Xác thực chữ ký
        if not verify_auth_info(auth_result['signature'], auth_result['auth_data'], sender_public_key):
            raise ValueError("Authentication failed")

        # Tạo và mã hóa khóa 3DES
        triple_des_key = generate_3des_key()
        encrypted_key = encrypt_3des_key(triple_des_key, receiver_public_key)

        # Lưu khóa vào session hai chiều
        created_at = datetime.now(vn_timezone)
        cursor.execute(
            "UPDATE sessions SET triple_des_key = ? WHERE user_id = ? AND contact_user_id = ?",
            (encrypted_key, sender_id, receiver_id)
        )
        cursor.execute(
            "UPDATE sessions SET triple_des_key = ? WHERE user_id = ? AND contact_user_id = ?",
            (encrypted_key, receiver_id, sender_id)
        )
        conn.commit()
        logger.info("Key exchange successful")
        return encrypted_key
    except Exception as e:
        conn.rollback()
        logger.error(f"Key exchange failed: {str(e)}")
        raise
    finally:
        conn.close()


def send_message(sender_id, receiver_id, message, sender_private_key, receiver_public_key):
    """Gửi tin nhắn mã hóa"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Tạo khóa mới cho mỗi tin nhắn
        triple_des_key = generate_3des_key()
        logger.debug(f"New 3DES key generated: {triple_des_key.hex()}")

        # Tạo gói tin nhắn
        packet = create_message_packet(message, triple_des_key, sender_private_key)
        logger.debug(f"Message packet created (IV: {packet['iv'][:10]}..., Cipher: {packet['cipher'][:10]}...)")

        # Mã hóa khóa bằng public key người nhận
        encrypted_key = encrypt_3des_key(triple_des_key, receiver_public_key)

        # Lưu khóa vào session
        created_at = datetime.now(vn_timezone)
        cursor.execute(
            "UPDATE sessions SET triple_des_key = ? WHERE user_id = ? AND contact_user_id = ?",
            (encrypted_key, sender_id, receiver_id)
        )
        cursor.execute(
            "UPDATE sessions SET triple_des_key = ? WHERE user_id = ? AND contact_user_id = ?",
            (encrypted_key, receiver_id, sender_id)
        )

        # Lưu tin nhắn
        cursor.execute(
            """INSERT INTO messages 
               (sender_id, receiver_id, ciphertext, iv, hash, signature, status, created_at) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (sender_id, receiver_id, packet['cipher'], packet['iv'],
             packet['hash'], packet['sig'], 'sent', created_at)
        )
        conn.commit()
        message_id = cursor.lastrowid
        logger.info(f"Message sent (ID: {message_id})")
        return message_id
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to send message: {str(e)}", exc_info=True)
        raise
    finally:
        conn.close()


def receive_message(receiver_id, sender_id, receiver_private_key, sender_public_key):
    """Nhận và giải mã tin nhắn"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Lấy tin nhắn chưa đọc
        cursor.execute(
            """SELECT iv, ciphertext, hash, signature FROM messages 
               WHERE receiver_id = ? AND sender_id = ? AND status = 'sent'""",
            (receiver_id, sender_id)
        )
        message = cursor.fetchone()

        if not message:
            logger.warning("No unread messages found")
            return None

        # Lấy khóa mã hóa từ session
        cursor.execute(
            "SELECT triple_des_key FROM sessions WHERE user_id = ? AND contact_user_id = ?",
            (receiver_id, sender_id)
        )
        session = cursor.fetchone()

        if not session or not session['triple_des_key']:
            raise ValueError("No encryption key found")

        # Giải mã khóa 3DES
        triple_des_key = decrypt_3des_key(session['triple_des_key'], receiver_private_key)
        logger.debug(f"Decrypted 3DES key: {triple_des_key.hex()}")

        # Tạo packet
        packet = {
            'iv': message['iv'],
            'cipher': message['ciphertext'],
            'hash': message['hash'],
            'sig': message['signature']
        }

        # Giải mã và xác thực
        plaintext, status = verify_and_decrypt_message(packet, triple_des_key, sender_public_key)

        if status != "ACK":
            raise ValueError(f"Verification failed: {status}")

        # Cập nhật trạng thái tin nhắn
        cursor.execute(
            "UPDATE messages SET status = 'delivered' WHERE receiver_id = ? AND sender_id = ? AND ciphertext = ?",
            (receiver_id, sender_id, message['ciphertext'])
        )
        conn.commit()
        logger.info("Message received and decrypted successfully")
        return plaintext
    except ValueError as ve:
        conn.rollback()
        logger.error(f"Message verification failed: {str(ve)}")
        return None
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to receive message: {str(e)}", exc_info=True)
        return None
    finally:
        conn.close()


def main():
    """Hàm chính để chạy test"""
    try:
        # 1. Khởi tạo database
        setup_db()

        # 2. Đăng ký 2 user
        print("\n=== Đăng ký user ===")
        user1_id, user1_public_key, user1_private_key = register_user("User1", "user1@example.com", "password123")
        user2_id, user2_public_key, user2_private_key = register_user("User2", "user2@example.com", "password123")

        # 3. Đăng nhập
        print("\n=== Đăng nhập ===")
        user1_id, user1_public_key, user1_private_key = login_user("user1@example.com", "password123")
        user2_id, user2_public_key, user2_private_key = login_user("user2@example.com", "password123")

        # 4. Gửi và xác nhận lời mời
        print("\n=== Kết bạn ===")
        token = send_invitation(user1_id, "user2@example.com")
        if not confirm_invitation(token):
            raise RuntimeError("Failed to confirm invitation")

        # 5. Handshake
        print("\n=== Handshake ===")
        session_id = handshake(user1_id, user2_id)
        if not session_id:
            raise RuntimeError("Handshake failed")

        # 6. Trao đổi khóa
        print("\n=== Trao đổi khóa ===")
        encrypted_key = exchange_key(
            user1_id, user2_id,
            user1_private_key, user1_public_key, user2_public_key
        )
        if not encrypted_key:
            raise RuntimeError("Key exchange failed")

        # 7. Gửi tin nhắn
        print("\n=== Gửi tin nhắn ===")
        message_id = send_message(
            user1_id, user2_id,
            "Xin chào từ User1!",
            user1_private_key, user2_public_key
        )
        if not message_id:
            raise RuntimeError("Failed to send message")

        # 8. Nhận tin nhắn
        print("\n=== Nhận tin nhắn ===")
        received_msg = receive_message(user2_id, user1_id, user2_private_key, user1_public_key)
        if received_msg:
            print(f"\n=== TEST THÀNH CÔNG ===\nTin nhắn nhận được: '{received_msg}'\n")
        else:
            print("\n=== TEST THẤT BẠI ===\nKhông nhận được tin nhắn\n")

    except Exception as e:
        logger.error(f"Test failed: {str(e)}", exc_info=True)
        print("\n=== TEST THẤT BẠI ===\n")


if __name__ == "__main__":
    main()