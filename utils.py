import logging
import base64
import os
import pytz
import time
from datetime import datetime

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1, PSS

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Đặt múi giờ Việt Nam
vn_timezone = pytz.timezone('Asia/Ho_Chi_Minh')


def get_current_vn_timestamp():
    """Lấy timestamp hiện tại theo múi giờ Việt Nam"""
    return int(datetime.now(vn_timezone).timestamp())


def generate_rsa_key_pair():
    """Tạo cặp khóa RSA 2048-bit"""
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        logger.info("Generated RSA key pair successfully")
        return public_pem, private_pem
    except Exception as e:
        logger.error(f"Failed to generate RSA key pair: {str(e)}")
        raise


def handshake_initiate():
    """Tạo tín hiệu handshake 'Hello!'"""
    logger.info("Initiating handshake with 'Hello!'")
    return "Hello!"


def handshake_respond():
    """Tạo phản hồi handshake 'Ready!'"""
    logger.info("Responding to handshake with 'Ready!'")
    return "Ready!"


def encrypt_3des_key(triple_des_key, rsa_public_key_pem):
    """Mã hóa khóa TripleDES bằng khóa công khai RSA (OAEP + SHA-256)"""
    try:
        if len(triple_des_key) != 24:
            logger.error("Invalid TripleDES key length: expected 24 bytes")
            raise ValueError("TripleDES key must be 24 bytes")

        public_key = serialization.load_pem_public_key(rsa_public_key_pem.encode())
        encrypted_key = public_key.encrypt(
            triple_des_key,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode()
    except Exception as e:
        logger.error(f"Failed to encrypt TripleDES key: {str(e)}")
        raise


def decrypt_3des_key(encrypted_key, rsa_private_key_pem):
    """Giải mã khóa TripleDES bằng khóa riêng RSA"""
    try:
        if not encrypted_key:
            logger.error("Encrypted key is empty")
            raise ValueError("Encrypted key is empty")

        private_key = serialization.load_pem_private_key(rsa_private_key_pem.encode(), password=None)
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        decrypted_key = private_key.decrypt(
            encrypted_key_bytes,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        if len(decrypted_key) != 24:
            logger.error(f"Decrypted TripleDES key has invalid length: {len(decrypted_key)} bytes")
            raise ValueError("Decrypted TripleDES key must be 24 bytes")

        return decrypted_key
    except Exception as e:
        logger.error(f"Failed to decrypt TripleDES key: {str(e)}")
        raise


def sign_auth_info(sender_id, receiver_id, rsa_private_key_pem):
    """Ký thông tin xác thực bằng RSA/SHA-256"""
    try:
        timestamp = get_current_vn_timestamp()
        auth_data = f"{sender_id}:{receiver_id}:{timestamp}"

        private_key = serialization.load_pem_private_key(rsa_private_key_pem.encode(), password=None)
        signature = private_key.sign(
            auth_data.encode(),
            PSS(
                mgf=MGF1(hashes.SHA256()),
                salt_length=padding.calculate_max_pss_salt_length(private_key, hashes.SHA256())
            ),
            hashes.SHA256()
        )

        logger.info(f"Signed auth info: sender={sender_id}, receiver={receiver_id}, timestamp={timestamp}")
        return {
            "auth_data": auth_data,
            "signature": base64.b64encode(signature).decode(),
            "timestamp": timestamp
        }
    except Exception as e:
        logger.error(f"Failed to sign auth info: {str(e)}")
        raise



def verify_auth_info(signature, auth_data, rsa_public_key_pem):
    try:
        # Kiểm tra định dạng auth_data
        parts = auth_data.split(':')
        if len(parts) != 3:
            logger.error(f"Invalid auth_data format: expected sender_id:receiver_id:timestamp, got {auth_data}")
            return False

        sender_id, receiver_id, timestamp = parts
        timestamp = int(timestamp)
        current_time = get_current_vn_timestamp()

        # Kiểm tra timestamp (cho phép lệch ±5 phút)
        if abs(current_time - timestamp) > 300:
            logger.error(f"Timestamp expired: {timestamp} (current: {current_time})")
            return False

        logger.debug(f"Auth Data for verify: {auth_data}")
        logger.debug(f"Signature for verify: {signature[:50] if isinstance(signature, str) else str(signature)[:50]}...")
        logger.debug(f"Public Key for verify: {rsa_public_key_pem[:50]}...")
        public_key = serialization.load_pem_public_key(rsa_public_key_pem.encode())
        public_key.verify(
            base64.b64decode(signature),
            auth_data.encode(),
            PSS(
                mgf=MGF1(algorithm=hashes.SHA256()),
                salt_length=PSS.AUTO
            ),
            hashes.SHA256()
        )

        logger.info(f"Verified auth info: sender={sender_id}, receiver={receiver_id}, timestamp={timestamp}")
        return True
    except Exception as e:
        logger.error(f"Failed to verify auth info: {str(e)}")
        return False

def generate_3des_key():
    """Tạo khóa TripleDES ngẫu nhiên (24 bytes)"""
    try:
        key = os.urandom(24)
        logger.info("Generated TripleDES key successfully")
        return key
    except Exception as e:
        logger.error(f"Failed to generate TripleDES key: {str(e)}")
        raise


def encrypt_message(message, triple_des_key):
    """Mã hóa tin nhắn bằng TripleDES (CBC mode) với padding đúng cách"""
    try:
        if len(triple_des_key) != 24:
            raise ValueError("TripleDES key must be 24 bytes")

        iv = os.urandom(8)
        padder = sym_padding.PKCS7(64).padder()  # Block size 64-bit cho TripleDES

        # Chuyển đổi message sang bytes nếu chưa phải
        message_bytes = message.encode() if isinstance(message, str) else message
        padded_data = padder.update(message_bytes) + padder.finalize()

        cipher = Cipher(TripleDES(triple_des_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}", exc_info=True)
        raise


def decrypt_message(ciphertext, iv, triple_des_key):
    """Giải mã tin nhắn với xử lý padding đúng cách"""
    try:
        if len(triple_des_key) != 24:
            raise ValueError("TripleDES key must be 24 bytes")

        iv_bytes = base64.b64decode(iv)
        ciphertext_bytes = base64.b64decode(ciphertext)

        cipher = Cipher(TripleDES(triple_des_key), modes.CBC(iv_bytes))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()

        # Xử lý padding
        unpadder = sym_padding.PKCS7(64).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode('utf-8')
    except ValueError as ve:
        logger.error(f"Padding error: {str(ve)}")
        raise ValueError("Invalid padding bytes")
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}", exc_info=True)
        raise

def compute_message_hash(iv, ciphertext):
    """Tính hash SHA-256 của IV || ciphertext"""
    try:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(base64.b64decode(iv) + base64.b64decode(ciphertext))
        return digest.finalize().hex()
    except Exception as e:
        logger.error(f"Failed to compute message hash: {str(e)}")
        raise


def sign_message(iv, ciphertext, rsa_private_key_pem):
    """Ký số tin nhắn (IV || ciphertext) bằng RSA/SHA-256"""
    try:
        private_key = serialization.load_pem_private_key(rsa_private_key_pem.encode(), password=None)
        data = base64.b64decode(iv) + base64.b64decode(ciphertext)
        signature = private_key.sign(
            data,
            PSS(
                mgf=MGF1(hashes.SHA256()),
                salt_length=padding.calculate_max_pss_salt_length(private_key, hashes.SHA256())
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    except Exception as e:
        logger.error(f"Failed to sign message: {str(e)}")
        raise


def verify_message(iv, ciphertext, signature, rsa_public_key_pem):
    """Xác minh chữ ký RSA và hash SHA-256 của tin nhắn"""
    try:
        public_key = serialization.load_pem_public_key(rsa_public_key_pem.encode())
        public_key.verify(
            base64.b64decode(signature),
            base64.b64decode(iv) + base64.b64decode(ciphertext),
            PSS(
                mgf=MGF1(algorithm=hashes.SHA256()),
                salt_length=PSS.AUTO
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Failed to verify message signature: {str(e)}")
        return False


def create_message_packet(message, triple_des_key, rsa_private_key_pem):
    """Tạo gói tin nhắn theo yêu cầu đề bài"""
    try:
        iv, ciphertext = encrypt_message(message, triple_des_key)
        hash_value = compute_message_hash(iv, ciphertext)
        signature = sign_message(iv, ciphertext, rsa_private_key_pem)

        return {
            "iv": iv,
            "cipher": ciphertext,
            "hash": hash_value,
            "sig": signature
        }
    except Exception as e:
        logger.error(f"Failed to create message packet: {str(e)}")
        raise


def verify_and_decrypt_message(packet, triple_des_key, rsa_public_key_pem):
    """Xác minh và giải mã với xử lý lỗi tốt hơn"""
    try:
        # Kiểm tra hash trước
        computed_hash = compute_message_hash(packet['iv'], packet['cipher'])
        if computed_hash != packet['hash']:
            return None, "NACK: Hash mismatch"

        # Kiểm tra chữ ký
        if not verify_message(packet['iv'], packet['cipher'], packet['sig'], rsa_public_key_pem):
            return None, "NACK: Invalid signature"

        # Giải mã
        message = decrypt_message(packet['cipher'], packet['iv'], triple_des_key)
        return message, "ACK"

    except ValueError as ve:
        logger.error(f"Decryption failed: {str(ve)}")
        return None, f"NACK: {str(ve)}"
    except Exception as e:
        logger.error(f"Verification failed: {str(e)}", exc_info=True)
        return None, f"NACK: {str(e)}"