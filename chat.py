import logging
import sqlite3
import socket
import json
from datetime import datetime
import pytz
from utils import (
    generate_rsa_key_pair, handshake_initiate, handshake_respond,
    encrypt_3des_key, decrypt_3des_key, sign_auth_info, verify_auth_info,
    generate_3des_key, create_message_packet, verify_and_decrypt_message
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
            "SELECT id, name, password_hash, rsa_public_key, rsa_private_key FROM users WHERE gmail = ?",
            (gmail,)
        )
        user = cursor.fetchone()
        if user and password == user['password_hash']:
            logger.info(f"User {gmail} logged in successfully")
            return user['id'], user['name'], user['rsa_public_key'], user['rsa_private_key']
        logger.warning(f"Login failed for {gmail}")
        return None, None, None, None
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
        token = "dummy_token_" + str(int(datetime.now(vn_timezone).timestamp()))
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
                cursor.execute(
                    "UPDATE invitations SET status = 'accepted' WHERE token = ?",
                    (token,)
                )
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

def get_user_info(user_id):
    """Lấy thông tin người dùng"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT name, rsa_public_key FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            return user['name'], user['rsa_public_key']
        return None, None
    finally:
        conn.close()

def send_message(sock, sender_id, receiver_id, message, triple_des_key, private_key):
    """Gửi tin nhắn mã hóa và lưu vào database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        packet = create_message_packet(message, triple_des_key, private_key)
        created_at = datetime.now(vn_timezone)
        cursor.execute(
            """INSERT INTO messages 
               (sender_id, receiver_id, ciphertext, iv, hash, signature, status, created_at) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (sender_id, receiver_id, packet['cipher'], packet['iv'], packet['hash'], packet['sig'], 'sent', created_at)
        )
        conn.commit()
        sock.sendall(json.dumps(packet).encode())
        logger.info(f"Message sent from {sender_id} to {receiver_id}")
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to send message: {str(e)}")
        raise
    finally:
        conn.close()

def receive_message(sock, receiver_id, sender_id, triple_des_key, private_key, public_key):
    """Nhận và giải mã tin nhắn, cập nhật database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        data = sock.recv(4096).decode()
        packet = json.loads(data)
        plaintext, status = verify_and_decrypt_message(packet, triple_des_key, public_key)
        if status != "ACK":
            sock.sendall(f"NACK: {status}".encode())
            raise ValueError(f"Verification failed: {status}")
        created_at = datetime.now(vn_timezone)
        cursor.execute(
            """INSERT INTO messages 
               (sender_id, receiver_id, ciphertext, iv, hash, signature, status, created_at) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (sender_id, receiver_id, packet['cipher'], packet['iv'], packet['hash'], packet['sig'], 'delivered', created_at)
        )
        conn.commit()
        sock.sendall("ACK".encode())
        logger.info(f"Message received by {receiver_id} from {sender_id}: {plaintext}")
        return plaintext
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to receive message: {str(e)}")
        sock.sendall(f"NACK: {str(e)}".encode())
        return None
    finally:
        conn.close()

def chat_loop(sock, user_id, user_name, contact_id, triple_des_key, private_key, contact_public_key):
    """Vòng lặp chat liên tục"""
    while True:
        message = input(f"{user_name}> ")
        if message.lower() == "exit":
            print("Exiting chat...")
            break
        send_message(sock, user_id, contact_id, message, triple_des_key, private_key)
        print(f"Sent: {message}")
        received_message = receive_message(sock, user_id, contact_id, triple_des_key, private_key, contact_public_key)
        if received_message:
            print(f"Received: {received_message}")
        else:
            print("Error receiving message")

def run_server(port=12345):
    """Chạy ở chế độ server"""
    setup_db()
    print("=== Server Mode ===")
    gmail = input("Enter email: ")
    password = input("Enter password: ")
    user_id, user_name, public_key, private_key = login_user(gmail, password)
    if not user_id:
        print("Login failed!")
        return
    print(f"Logged in as {user_name} (ID: {user_id})")
    contact_gmail = input("Enter contact's email: ")
    token = send_invitation(user_id, contact_gmail)
    print(f"Invitation sent. Token: {token}")
    if not confirm_invitation(token):
        print("Invitation confirmation failed!")
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE gmail = ?", (contact_gmail,))
    contact = cursor.fetchone()
    if not contact:
        print("Contact not found!")
        conn.close()
        return
    contact_id = contact['id']
    _, contact_public_key = get_user_info(contact_id)
    conn.close()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', port))
        s.listen()
        print(f"Server listening on port {port}...")
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024).decode()
            if data != handshake_initiate():
                print("Handshake failed!")
                return
            conn.sendall(handshake_respond().encode())
            conn.sendall(public_key.encode())
            contact_public_key = conn.recv(4096).decode()
            data = conn.recv(4096).decode()
            packet = json.loads(data)
            auth_data = f"{contact_id}:{user_id}:{packet['timestamp']}"
            if not verify_auth_info(packet["signed_info"], auth_data, contact_public_key):
                conn.sendall("NACK: Authentication Failed!".encode())
                print("Authentication failed!")
                return
            triple_des_key = decrypt_3des_key(packet["encrypted_3des_key"], private_key)
            conn.sendall("ACK".encode())
            print("Key exchange completed. Starting chat...")
            chat_loop(conn, user_id, user_name, contact_id, triple_des_key, private_key, contact_public_key)

def run_client(host='localhost', port=12345):
    """Chạy ở chế độ client"""
    setup_db()
    print("=== Client Mode ===")
    gmail = input("Enter email: ")
    password = input("Enter password: ")
    user_id, user_name, public_key, private_key = login_user(gmail, password)
    if not user_id:
        print("Login failed!")
        return
    print(f"Logged in as {user_name} (ID: {user_id})")
    contact_gmail = input("Enter contact's email: ")
    token = send_invitation(user_id, contact_gmail)
    print(f"Invitation sent. Token: {token}")
    if not confirm_invitation(token):
        print("Invitation confirmation failed!")
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE gmail = ?", (contact_gmail,))
    contact = cursor.fetchone()
    if not contact:
        print("Contact not found!")
        conn.close()
        return
    contact_id = contact['id']
    _, contact_public_key = get_user_info(contact_id)
    conn.close()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(handshake_initiate().encode())
        response = s.recv(1024).decode()
        if response != handshake_respond():
            print("Handshake failed!")
            return
        s.sendall(public_key.encode())
        contact_public_key = s.recv(4096).decode()
        auth_packet = sign_auth_info(user_id, contact_id, private_key)
        triple_des_key = generate_3des_key()
        encrypted_key = encrypt_3des_key(triple_des_key, contact_public_key)
        packet = {
            "signed_info": auth_packet["signature"],
            "encrypted_3des_key": encrypted_key,
            "timestamp": auth_packet["timestamp"]
        }
        s.sendall(json.dumps(packet).encode())
        response = s.recv(1024).decode()
        if "NACK" in response:
            print(f"Authentication failed: {response}")
            return
        print("Key exchange completed. Starting chat...")
        chat_loop(s, user_id, user_name, contact_id, triple_des_key, private_key, contact_public_key)

if __name__ == "__main__":
    mode = input("Run as (server/client): ").lower()
    if mode == "server":
        run_server()
    elif mode == "client":
        run_client()
    else:
        print("Invalid mode! Choose 'server' or 'client'.")