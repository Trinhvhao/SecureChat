from flask import Blueprint, jsonify, request, render_template, redirect, url_for, session
from app import db, app
from models import User, Invitation, Message, Contact, Session
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
from config import Config
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
from datetime import datetime, timedelta
from functools import wraps
import logging
import base64
import re
import requests

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Tắt log HTTP requests của Werkzeug
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# Đặt múi giờ Việt Nam
vn_timezone = Config.TIMEZONE

bp = Blueprint('routes', __name__)

# Decorator kiểm tra đăng nhập
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logger.warning(f"Session user_id not found, redirecting to auth. Session: {dict(session)}")
            return redirect(url_for('routes.auth', next=request.url))
        user = User.query.get(session['user_id'])
        if not user:
            logger.warning(f"User not found for user_id={session['user_id']}, clearing session")
            session.pop('user_id', None)
            return redirect(url_for('routes.auth', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Hàm gửi email lời mời
def send_invitation_email(sender_gmail, receiver_gmail, token):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", receiver_gmail):
        logger.error(f"Invalid email format: {receiver_gmail}")
        return False
    msg = MIMEMultipart()
    msg['From'] = Config.SMTP_EMAIL
    msg['To'] = receiver_gmail
    msg['Subject'] = f"Invitation to join secure chat from {sender_gmail}"
    confirmation_link = f"{request.url_root}confirm_invitation?token={token}"
    body = f"""
    Hi,

    {sender_gmail} has invited you to join a secure chat application.
    Please click the link below to accept the invitation:

    {confirmation_link}

    If you haven't registered yet, please sign up first.
    """
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT)
        server.starttls()
        server.login(Config.SMTP_EMAIL, Config.SMTP_PASSWORD)
        server.sendmail(Config.SMTP_EMAIL, receiver_gmail, msg.as_string())
        server.quit()
        logger.info(f"Sent invitation email to {receiver_gmail} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {receiver_gmail}: {str(e)}")
        return False

# Route mặc định
@bp.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return redirect(url_for('routes.chat'))
    return redirect(url_for('routes.auth'))

# Route render trang auth
@bp.route('/auth', methods=['GET'])
def auth():
    logger.debug(f"Session data: {dict(session)}")
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            if 'session_start' in session:
                session_age = datetime.now(vn_timezone) - session['session_start']
                if session_age > app.config['PERMANENT_SESSION_LIFETIME']:
                    logger.warning(f"Session expired for user_id={user.id}")
                    session.clear()
                    return render_template('auth.html', error="Session expired, please log in again")
            return redirect(url_for('routes.chat'))
    return render_template('auth.html')

# Route đăng nhập
@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    gmail = data.get('gmail')
    password = data.get('password')
    next_url = request.args.get('next')
    if not gmail or not password:
        logger.error("Login failed: Missing required fields")
        return jsonify({"error": "Gmail and password are required"}), 400
    try:
        user = User.query.filter_by(gmail=gmail).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['session_start'] = datetime.now(vn_timezone)
            session.permanent = True
            logger.info(f"User logged in successfully: {gmail}, user_id={user.id} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
            return jsonify({
                "status": "success",
                "message": "Login successful",
                "redirect": next_url or url_for('routes.chat')
            }), 200
        logger.error(f"Login failed for {gmail}: Invalid credentials")
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        return jsonify({"error": f"Login error: {str(e)}"}), 500

# Route đăng ký
@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    gmail = data.get('gmail')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    if not name or not gmail or not password or not confirm_password:
        logger.error("Registration failed: Missing required fields")
        return jsonify({"error": "All fields are required"}), 400
    if not re.match(r"[^@]+@[^@]+\.[^@]+", gmail):
        logger.error(f"Registration failed: Invalid email format: {gmail}")
        return jsonify({"error": "Invalid email format"}), 400
    if password != confirm_password:
        logger.error("Registration failed: Passwords do not match")
        return jsonify({"error": "Passwords do not match"}), 400
    if User.query.filter_by(gmail=gmail).first():
        logger.error(f"Registration failed: Gmail already registered: {gmail}")
        return jsonify({"error": "Gmail already registered"}), 400
    try:
        public_key, private_key = generate_rsa_key_pair()
        user = User(
            name=name,
            gmail=gmail,
            password_hash=generate_password_hash(password),
            rsa_public_key=public_key,
            rsa_private_key=private_key,
            created_at=datetime.now(vn_timezone)
        )
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        session['session_start'] = datetime.now(vn_timezone)
        session.permanent = True
        logger.info(f"User registered successfully: {gmail}, user_id={user.id} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
        return jsonify({
            "status": "success",
            "message": "User registered successfully",
            "redirect": url_for('routes.chat')
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration failed: {str(e)}")
        return jsonify({"error": f"Failed to register user: {str(e)}"}), 500

# Route đăng xuất
@bp.route('/logout')
def logout():
    session.clear()
    response = redirect(url_for('routes.auth'))
    response.delete_cookie(app.config['SESSION_COOKIE_NAME'])
    logger.info("User logged out successfully")
    return response

# Route gửi lời mời
@bp.route('/send_invitation', methods=['POST'])
@login_required
def send_invitation():
    user_id = session['user_id']
    user = User.query.get(user_id)
    data = request.get_json()
    receiver_gmail = data.get('receiver_gmail')
    if not receiver_gmail or not re.match(r"[^@]+@[^@]+\.[^@]+", receiver_gmail):
        logger.error(f"Invalid receiver email: {receiver_gmail}")
        return jsonify({"status": "error", "message": "Invalid receiver email"}), 400
    try:
        token = str(uuid.uuid4())
        invitation = Invitation(
            sender_id=user_id,
            receiver_gmail=receiver_gmail,
            token=token,
            created_at=datetime.now(vn_timezone),
            expires_at=datetime.now(vn_timezone) + timedelta(days=1)
        )
        db.session.add(invitation)
        db.session.commit()
        if send_invitation_email(user.gmail, receiver_gmail, token):
            logger.info(f"Invitation sent from {user.gmail} to {receiver_gmail} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
            return jsonify({"status": "success", "message": "Invitation sent successfully"}), 200
        logger.error(f"Failed to send invitation email to {receiver_gmail}")
        return jsonify({"status": "error", "message": "Failed to send invitation email"}), 500
    except Exception as e:
        db.session.rollback()
        logger.error(f"Send invitation failed: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to send invitation: {str(e)}"}), 500

# Route xác nhận lời mời
@bp.route('/confirm_invitation', methods=['GET'])
def confirm_invitation():
    token = request.args.get('token')
    try:
        invitation = Invitation.query.filter_by(token=token).first()
        if not invitation:
            logger.error(f"Invalid or expired token: {token}")
            return render_template('auth.html', error="Invalid or expired token")

        expires_at = invitation.expires_at.replace(tzinfo=vn_timezone) if invitation.expires_at.tzinfo is None else invitation.expires_at
        if expires_at < datetime.now(vn_timezone):
            logger.error(f"Invitation expired: token={token}")
            return render_template('auth.html', error="Invitation has expired")

        receiver = User.query.filter_by(gmail=invitation.receiver_gmail).first()
        if not receiver:
            logger.error(f"Receiver not registered: {invitation.receiver_gmail}")
            return render_template('auth.html', error="Receiver not registered. Please sign up first.")

        if invitation.status != 'pending':
            logger.error(f"Invitation already processed: token={token}")
            return render_template('auth.html', error="Invitation already processed")

        if 'user_id' in session and session['user_id'] != receiver.id:
            session.pop('user_id', None)
            return redirect(url_for('routes.auth', error="Please log in with the invited account", next=url_for('routes.confirm_invitation', token=token)))

        if 'user_id' not in session:
            return redirect(url_for('routes.auth', next=url_for('routes.confirm_invitation', token=token)))

        if session['user_id'] != receiver.id:
            return render_template('auth.html', error="You must log in with the invited account")

        if Contact.query.filter_by(user_id=invitation.sender_id, contact_user_id=receiver.id).first():
            logger.warning(f"Contact already exists: sender_id={invitation.sender_id}, receiver_id={receiver.id}")
            return redirect(url_for('routes.chat', message="Contact already exists"))

        invitation.status = 'accepted'
        contact1 = Contact(user_id=invitation.sender_id, contact_user_id=receiver.id, created_at=datetime.now(vn_timezone))
        contact2 = Contact(user_id=receiver.id, contact_user_id=invitation.sender_id, created_at=datetime.now(vn_timezone))
        db.session.add_all([contact1, contact2])
        db.session.commit()
        logger.info(f"Invitation accepted: sender_id={invitation.sender_id}, receiver_gmail={invitation.receiver_gmail} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
        return redirect(url_for('routes.chat', message="Invitation accepted. You can now chat!"))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Confirm invitation failed: {str(e)}")
        return render_template('auth.html', error=f"Failed to confirm invitation: {str(e)}")

# Route handshake
@bp.route('/handshake', methods=['POST'])
@login_required
def handshake():
    user_id = session['user_id']
    user = User.query.get(user_id)
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    signal = data.get('signal')
    try:
        receiver = User.query.get(receiver_id)
        if not receiver:
            logger.error(f"Invalid receiver_id={receiver_id}")
            return jsonify({"status": "error", "message": "Invalid receiver ID"}), 400

        if signal == handshake_initiate():
            logger.info(f"Handshake initiated by user_id={user_id} to receiver_id={receiver_id} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
            return jsonify({
                "status": "success",
                "response": handshake_respond(),
                "public_key": receiver.rsa_public_key
            }), 200
        elif signal == handshake_respond():
            if user_id == receiver_id:
                logger.error(f"Invalid handshake: user_id={user_id} cannot respond to own handshake")
                return jsonify({"status": "error", "message": "Cannot respond to own handshake"}), 400

            existing_session = Session.query.filter_by(user_id=user_id, contact_user_id=receiver_id).first()
            if existing_session:
                logger.warning(f"Session already exists: user_id={user_id}, receiver_id={receiver_id}")
                return jsonify({
                    "status": "success",
                    "message": "Session already exists",
                    "session_id": existing_session.id
                }), 200

            db_session = Session(
                user_id=user_id,
                contact_user_id=receiver_id,
                created_at=datetime.now(vn_timezone)
            )
            db.session.add(db_session)
            db.session.commit()
            logger.info(f"Handshake completed: session_id={db_session.id}, user_id={user_id}, receiver_id={receiver_id} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
            return jsonify({
                "status": "success",
                "message": "Handshake completed",
                "session_id": db_session.id
            }), 200

        logger.error(f"Invalid handshake signal: {signal}")
        return jsonify({"status": "error", "message": "Invalid handshake signal"}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Handshake failed: {str(e)}")
        return jsonify({"status": "error", "message": f"Handshake error: {str(e)}"}), 500

# Route trao đổi khóa
@bp.route('/exchange_key', methods=['POST'])
@login_required
def exchange_key():
    user_id = session['user_id']
    user = User.query.get(user_id)
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    signed_info = data.get('signed_info')
    try:
        receiver = User.query.get(receiver_id)
        if not receiver:
            logger.error(f"Invalid receiver_id={receiver_id}")
            return jsonify({"status": "error", "message": "Invalid receiver ID"}), 400

        db_session = Session.query.filter_by(user_id=user_id, contact_user_id=receiver_id).first()
        if not db_session:
            logger.error(f"Session not found: user_id={user_id}, receiver_id={receiver_id}")
            return jsonify({
                "status": "error",
                "message": "Session not found. Please complete handshake first."
            }), 404

        auth_data = signed_info.get('auth_data')
        signature = signed_info.get('signature')
        if not isinstance(signature, str):
            logger.error(f"Invalid signature format: expected string, got {type(signature)}")
            return jsonify({"status": "error", "message": "Invalid signature format"}), 400

        if verify_auth_info(signature, auth_data, user.rsa_public_key):
            triple_des_key = generate_3des_key()
            encrypted_key_for_sender = encrypt_3des_key(triple_des_key, user.rsa_public_key)
            encrypted_key_for_receiver = encrypt_3des_key(triple_des_key, receiver.rsa_public_key)

            db_session.triple_des_key = encrypted_key_for_sender
            reverse_session = Session.query.filter_by(user_id=receiver_id, contact_user_id=user_id).first()
            if not reverse_session:
                reverse_session = Session(
                    user_id=receiver_id,
                    contact_user_id=user_id,
                    created_at=datetime.now(vn_timezone)
                )
                db.session.add(reverse_session)
            reverse_session.triple_des_key = encrypted_key_for_receiver
            db.session.commit()
            logger.info(f"Key exchanged successfully: session_id={db_session.id}, user_id={user_id}, receiver_id={receiver_id} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
            return jsonify({
                "status": "success",
                "message": "Key exchanged successfully",
                "encrypted_3des_key_for_sender": encrypted_key_for_sender,
                "encrypted_3des_key_for_receiver": encrypted_key_for_receiver
            }), 200

        logger.error(f"Authentication failed: auth_data={auth_data}, signature={signature[:50]}...")
        return jsonify({"status": "error", "message": "Authentication failed"}), 401
    except Exception as e:
        db.session.rollback()
        logger.error(f"Exchange key failed: {str(e)}")
        return jsonify({"status": "error", "message": f"Key exchange failed: {str(e)}"}), 500

# Route gửi tin nhắn
@bp.route('/send_message', methods=['POST'])
@login_required
def send_message():
    user_id = session['user_id']
    user = User.query.get(user_id)
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    try:
        receiver = User.query.get(receiver_id)
        if not receiver:
            logger.error(f"Invalid receiver_id={receiver_id}")
            return jsonify({"status": "error", "message": "Invalid receiver ID"}), 400

        db_session = Session.query.filter_by(user_id=user_id, contact_user_id=receiver_id).first()
        if not db_session:
            db_session = Session(
                user_id=user_id,
                contact_user_id=receiver_id,
                created_at=datetime.now(vn_timezone)
            )
            db.session.add(db_session)
            db.session.commit()

        if not db_session.triple_des_key:
            reverse_session = Session.query.filter_by(user_id=receiver_id, contact_user_id=user_id).first()
            if not reverse_session:
                reverse_session = Session(
                    user_id=receiver_id,
                    contact_user_id=user_id,
                    created_at=datetime.now(vn_timezone)
                )
                db.session.add(reverse_session)
                db.session.commit()

            handshake_response = requests.post(
                url_for('routes.handshake', _external=True),
                json={"receiver_id": receiver_id, "signal": handshake_initiate()},
                headers={'Cookie': request.headers.get('Cookie')}
            )
            if handshake_response.status_code != 200 or handshake_response.json().get('status') != 'success':
                logger.error(f"Handshake initiation failed for user_id={user_id}, receiver_id={receiver_id}")
                return jsonify({"status": "error", "message": "Handshake initiation failed"}), 500

            handshake_response = requests.post(
                url_for('routes.handshake', _external=True),
                json={"receiver_id": receiver_id, "signal": handshake_respond()},
                headers={'Cookie': request.headers.get('Cookie')}
            )
            if handshake_response.status_code != 200 or handshake_response.json().get('status') != 'success':
                logger.error(f"Handshake response failed for user_id={user_id}, receiver_id={receiver_id}")
                return jsonify({"status": "error", "message": "Handshake response failed"}), 500

            rsa_private_key_pem = user.rsa_private_key if isinstance(user.rsa_private_key, str) else user.rsa_private_key.decode('utf-8')
            signed_info = sign_auth_info(user_id, receiver_id, rsa_private_key_pem)
            exchange_response = requests.post(
                url_for('routes.exchange_key', _external=True),
                json={"receiver_id": receiver_id, "signed_info": signed_info, "timestamp": signed_info['timestamp']},
                headers={'Cookie': request.headers.get('Cookie')}
            )
            if exchange_response.status_code != 200 or exchange_response.json().get('status') != 'success':
                logger.error(f"Key exchange failed for user_id={user_id}, receiver_id={receiver_id}: {exchange_response.json().get('message')}")
                return jsonify({"status": "error", "message": "Key exchange failed"}), 500

            db_session.triple_des_key = exchange_response.json().get('encrypted_3des_key_for_sender')
            db.session.commit()

        triple_des_key = decrypt_3des_key(db_session.triple_des_key, user.rsa_private_key)
        packet = create_message_packet(message, triple_des_key, user.rsa_private_key)
        msg = Message(
            sender_id=user_id,
            receiver_id=receiver_id,
            ciphertext=packet['cipher'],
            iv=packet['iv'],
            hash=packet['hash'],
            signature=packet['sig'],
            created_at=datetime.now(vn_timezone),
            status='sent'
        )
        db.session.add(msg)
        db.session.commit()
        logger.info(f"Message sent successfully: message_id={msg.id}, user_id={user_id}, receiver_id={receiver_id} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
        return jsonify({
            "status": "success",
            "message": "Message sent successfully",
            "message_id": msg.id
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Send message failed: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to process message: {str(e)}"}), 500

# Route khung chat
@bp.route('/chat', methods=['GET'])
@bp.route('/chat/<int:contact_id>', methods=['GET'])
@login_required
def chat(contact_id=None):
    user_id = session['user_id']
    user = User.query.get(user_id)
    if not user:
        logger.warning(f"User not found for user_id={user_id}, clearing session")
        session.pop('user_id', None)
        return redirect(url_for('routes.auth', error="Session invalid, please log in again"))

    try:
        contacts = Contact.query.filter_by(user_id=user_id).join(User, User.id == Contact.contact_user_id).all()
        message = request.args.get('message')

        # Lấy số tin nhắn chưa đọc cho tất cả liên hệ
        unread_counts = {}
        for contact in contacts:
            count = Message.query.filter_by(
                sender_id=contact.contact_user_id,
                receiver_id=user_id,
                status='sent'
            ).count()
            unread_counts[contact.contact_user_id] = count

        if contact_id is None:
            logger.info(f"Loaded contacts for user_id={user_id} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
            return render_template('chat.html', user=user, contacts=contacts, message=message, active_contact=None, unread_counts=unread_counts)

        contact = User.query.get(contact_id)
        if not contact:
            logger.error(f"Invalid contact: contact_id={contact_id}")
            return render_template('chat.html', user=user, contacts=contacts, message="Invalid contact", active_contact=None, unread_counts=unread_counts)

        db_session = Session.query.filter_by(user_id=user_id, contact_user_id=contact_id).first()
        if not db_session:
            db_session = Session(user_id=user_id, contact_user_id=contact_id, created_at=datetime.now(vn_timezone))
            db.session.add(db_session)
            db.session.commit()

        if not db_session.triple_des_key:
            rsa_private_key_pem = user.rsa_private_key if isinstance(user.rsa_private_key, str) else user.rsa_private_key.decode('utf-8')
            signed_info = sign_auth_info(user_id, contact_id, rsa_private_key_pem)
            if verify_auth_info(signed_info['signature'], signed_info['auth_data'], user.rsa_public_key):
                triple_des_key = generate_3des_key()
                encrypted_key_for_user = encrypt_3des_key(triple_des_key, user.rsa_public_key)
                encrypted_key_for_contact = encrypt_3des_key(triple_des_key, contact.rsa_public_key)
                db_session.triple_des_key = encrypted_key_for_user
                reverse_session = Session.query.filter_by(user_id=contact_id, contact_user_id=user_id).first()
                if not reverse_session:
                    reverse_session = Session(user_id=contact_id, contact_user_id=user_id, created_at=datetime.now(vn_timezone))
                    db.session.add(reverse_session)
                reverse_session.triple_des_key = encrypted_key_for_contact
                db.session.commit()
                logger.info(f"Key exchanged for session: session_id={db_session.id}, user_id={user_id}, contact_id={contact_id}")
        logger.info(f"Loaded chat for user_id={user_id}, contact_id={contact_id} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
        return render_template('chat.html', user=user, contacts=contacts, active_contact=contact, unread_counts=unread_counts)

    except Exception as e:
        logger.error(f"Failed to load chat: user_id={user_id}, contact_id={contact_id}, error={str(e)}")
        return render_template('chat.html', user=user, contacts=contacts, error=f"Failed to load chat: {str(e)}", active_contact=None, unread_counts=unread_counts)

# Route lấy tin nhắn mới
@bp.route('/get_messages/<int:contact_id>', methods=['GET'])
@login_required
def get_messages(contact_id):
    user_id = session['user_id']
    user = User.query.get(user_id)
    try:
        contact = User.query.get(contact_id)
        if not contact:
            logger.error(f"Invalid contact: contact_id={contact_id}")
            return jsonify({"status": "error", "message": "Invalid contact"}), 400

        db_session = Session.query.filter_by(user_id=user_id, contact_user_id=contact_id).first()
        if not db_session or not db_session.triple_des_key:
            logger.error(f"Session or key not found: user_id={user_id}, contact_id={contact_id}")
            return jsonify({"status": "error", "message": "Session or key not found"}), 404

        last_id = request.args.get('last_id', 0, type=int)
        messages = Message.query.filter(
            Message.id > last_id,
            ((Message.sender_id == user_id) & (Message.receiver_id == contact_id)) |
            ((Message.sender_id == contact_id) & (Message.receiver_id == user_id))
        ).order_by(Message.id.asc()).all()

        decrypted_messages = []
        triple_des_key = decrypt_3des_key(db_session.triple_des_key, user.rsa_private_key)
        for msg in messages:
            packet = {"iv": msg.iv, "cipher": msg.ciphertext, "hash": msg.hash, "sig": msg.signature}
            sender_public_key = User.query.get(msg.sender_id).rsa_public_key
            plaintext, status = verify_and_decrypt_message(packet, triple_des_key, sender_public_key)
            decrypted_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "sender_name": User.query.get(msg.sender_id).name,
                "plaintext": plaintext if status == "ACK" else "Error: " + status,
                "created_at": msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        return jsonify({"status": "success", "messages": decrypted_messages}), 200
    except Exception as e:
        logger.error(f"Failed to retrieve messages: user_id={user_id}, contact_id={contact_id}, error={str(e)}")
        return jsonify({"status": "error", "message": f"Failed to retrieve messages: {str(e)}"}), 500

# Route đánh dấu tin nhắn đã đọc
@bp.route('/mark_as_read/<int:contact_id>', methods=['POST'])
@login_required
def mark_as_read(contact_id):
    user_id = session['user_id']
    try:
        contact = User.query.get(contact_id)
        if not contact:
            logger.error(f"Invalid contact: contact_id={contact_id}")
            return jsonify({"status": "error", "message": "Invalid contact"}), 400

        messages = Message.query.filter_by(
            sender_id=contact_id,
            receiver_id=user_id,
            status='sent'
        ).all()
        for msg in messages:
            msg.status = 'received'
        db.session.commit()
        logger.info(f"Marked messages as read for user_id={user_id}, contact_id={contact_id} at {datetime.now(vn_timezone).strftime('%Y-%m-%d %H:%M:%S')}")
        return jsonify({"status": "success", "message": "Messages marked as read"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to mark messages as read: user_id={user_id}, contact_id={contact_id}, error={str(e)}")
        return jsonify({"status": "error", "message": f"Failed to mark messages as read: {str(e)}"}), 500

# Route lấy số tin nhắn chưa đọc cho tất cả liên hệ
@bp.route('/get_unread_counts', methods=['GET'])
@login_required
def get_unread_counts():
    user_id = session['user_id']
    try:
        contacts = Contact.query.filter_by(user_id=user_id).all()
        unread_counts = {}
        for contact in contacts:
            count = Message.query.filter_by(
                sender_id=contact.contact_user_id,
                receiver_id=user_id,
                status='sent'
            ).count()
            unread_counts[str(contact.contact_user_id)] = count  # Chuyển contact_id thành string để đồng bộ với client
        logger.info(f"Retrieved unread counts for user_id={user_id}: {unread_counts}")
        return jsonify({"status": "success", "unread_counts": unread_counts}), 200
    except Exception as e:
        logger.error(f"Failed to get unread counts: user_id={user_id}, error={str(e)}")
        return jsonify({"status": "error", "message": f"Failed to get unread counts: {str(e)}"}), 500