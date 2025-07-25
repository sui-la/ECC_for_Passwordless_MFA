from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
from database.models import db
from database.db_operations import add_user, get_user_by_email
import redis
from utils.security import generate_nonce
import jwt
from datetime import datetime, timedelta
from crypto.ecdsa_handler import verify_signature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import binascii
import traceback
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import uuid
from database.models import Session, AuthLog
from utils.email_utils import send_notification_email
from mail import mail
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# AES-GCM encryption/decryption utilities

def derive_aes_key_from_shared_secret(shared_secret: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    return digest.finalize()

def aes_gcm_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag

def aes_gcm_decrypt(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"], supports_credentials=True)
app.config.from_object(Config)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)
db.init_app(app)

redis_client = redis.StrictRedis.from_url(app.config['REDIS_URL'], decode_responses=True)

mail.init_app(app)

def raw_to_der(raw_sig):
    r = int.from_bytes(raw_sig[:32], byteorder='big')
    s = int.from_bytes(raw_sig[32:], byteorder='big')
    return encode_dss_signature(r, s)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok'}), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    public_key_pem = data.get('public_key_pem')
    if not email or not public_key_pem:
        return jsonify({'error': 'Email and public_key_pem are required.'}), 400
    user = get_user_by_email(email)
    if user:
        # Update the user's public key
        user.public_key = public_key_pem.encode('utf-8')
        db.session.commit()
        send_notification_email(
            subject="Your public key was updated",
            recipient=email,
            body="Your public key for ECC Passwordless MFA was updated. If this wasn't you, please contact support."
        )
        return jsonify({'message': 'User public key updated successfully.'}), 200
    add_user(email, public_key_pem.encode('utf-8'))
    send_notification_email(
        subject="Welcome to ECC Passwordless MFA!",
        recipient=email,
        body="Thank you for registering. Your account is now active."
    )
    # Send registration email
    try:
        send_email(email, 'Welcome to ECC MFA', 'Thank you for registering with ECC Passwordless MFA!')
    except Exception as e:
        print(f'Failed to send registration email: {e}')
    return jsonify({'message': 'User registered successfully.'}), 201

@app.route('/auth/challenge', methods=['POST'])
def auth_challenge():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required.'}), 400
    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    nonce = generate_nonce()
    redis_client.setex(f'auth_nonce:{email}', 300, nonce)  # 5 min expiry
    return jsonify({'nonce': nonce}), 200

@app.route('/auth/verify', methods=['POST'])
def auth_verify():
    data = request.get_json()
    email = data.get('email')
    signature = data.get('signature')
    print("==== DEBUG START ====")
    # print("Email:", email)
    # print("Signature (raw):", signature)
    user = get_user_by_email(email)
    if not user:
        print("User not found")
        return jsonify({'error': 'User not found.'}), 404
    nonce = redis_client.get(f'auth_nonce:{email}')
    print("Nonce from Redis:", nonce)
    if not nonce:
        print("No nonce found")
        return jsonify({'error': 'Challenge expired or not found.'}), 400
    try:
        # Always decode as base64
        try:
            signature_bytes = base64.b64decode(signature)
            # print("Signature decoded as base64:", binascii.hexlify(signature_bytes))
        except Exception as e:
            print("Base64 decode failed:", e)
            return jsonify({'error': 'Signature decode failed.'}), 400

        # print("Signature bytes length:", len(signature_bytes))
        # print("Nonce (utf-8):", nonce.encode('utf-8'))
        # print("Nonce (raw):", nonce)
        # print("Public key PEM:", user.public_key)
        public_key = serialization.load_pem_public_key(user.public_key)
        print("Verifying signature...")
        der_sig = raw_to_der(signature_bytes)
        public_key.verify(der_sig, nonce.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        print("Signature verification succeeded.")
        # Update last_login
        user.last_login = datetime.utcnow()
        db.session.commit()
        # Create a new session
        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=1)
        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            is_active=True
        )
        db.session.add(session)
        db.session.commit()
        # --- ECDH Key Exchange: Generate ephemeral ECDH key pair ---
        from crypto.ecc_operations import generate_private_key, get_public_key, serialize_public_key
        server_ecdh_private_key = generate_private_key()
        server_ecdh_public_key = get_public_key(server_ecdh_private_key)
        server_ecdh_public_pem = serialize_public_key(server_ecdh_public_key)
        # Store the server's ECDH private key in Redis, keyed by session_id (PEM serialized)
        server_ecdh_private_pem = server_ecdh_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        redis_client.setex(f'ecdh_privkey:{session_id}', 3600, server_ecdh_private_pem.decode('utf-8'))
        # --- End ECDH Key Exchange ---
        # Log successful authentication
        log = AuthLog(
            log_id=str(uuid.uuid4()),
            user_id=user.user_id,
            event_type='login_success',
            timestamp=datetime.utcnow(),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(log)
        db.session.commit()
        payload = {
            'user_id': user.user_id,
            'email': user.email,
            'exp': expires_at,
            'session_id': session_id
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        redis_client.delete(f'auth_nonce:{email}')
        print("==== DEBUG END ====")
        # Send login notification email
        try:
            send_email(email, 'Login Alert', 'You have successfully logged in to ECC MFA.')
        except Exception as e:
            print(f'Failed to send login email: {e}')
        send_notification_email(
            subject="New Login to Your Account",
            recipient=email,
            body=f"A new login to your ECC Passwordless MFA account was detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}. If this wasn't you, please contact support."
        )
        # --- Return server's ECDH public key in response ---
        return jsonify({'token': token, 'server_ecdh_public_key': server_ecdh_public_pem.decode('utf-8')}), 200
    except Exception as e:
        print("Verification exception:", str(e))
        traceback.print_exc()
        # Log failed authentication
        user_id = user.user_id if 'user' in locals() and user else None
        log = AuthLog(
            log_id=str(uuid.uuid4()),
            user_id=user_id,
            event_type='login_failure',
            timestamp=datetime.utcnow(),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=False
        )
        db.session.add(log)
        db.session.commit()
        print("==== DEBUG END ====")
        return jsonify({'error': f'Invalid signature: {str(e)}'}), 401
    print("==== DEBUG END ====")

@app.route('/profile', methods=['GET'])
def get_profile():
    """Get user profile information."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        email = payload.get('email')
        
        if not user_id or not email:
            return jsonify({'error': 'Invalid token.'}), 401
        
        user = get_user_by_email(email)
        if not user:
            return jsonify({'error': 'User not found.'}), 404
        
        # Format last_login for display
        last_login = None
        if user.last_login:
            last_login = user.last_login.strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return jsonify({
            'email': user.email,
            'last_login': last_login,
            'created_at': user.registration_date.strftime('%Y-%m-%d %H:%M:%S UTC') if user.registration_date else None
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        print(f"Profile error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/session/ecdh', methods=['POST'])
def session_ecdh():
    """Receive client's ECDH public key, derive shared secret, and store it for the session."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        data = request.get_json()
        client_ecdh_public_pem = data.get('client_ecdh_public_key')
        if not client_ecdh_public_pem:
            return jsonify({'error': 'client_ecdh_public_key is required.'}), 400
        # Retrieve server's ECDH private key from Redis
        server_ecdh_private_pem = redis_client.get(f'ecdh_privkey:{session_id}')
        if not server_ecdh_private_pem:
            return jsonify({'error': 'Server ECDH private key not found or expired.'}), 400
        from cryptography.hazmat.primitives import serialization
        from crypto.ecdh_handler import derive_shared_secret
        # Load server's ECDH private key
        server_ecdh_private_key = serialization.load_pem_private_key(
            server_ecdh_private_pem.encode('utf-8'), password=None
        )
        # Load client's ECDH public key
        client_ecdh_public_key = serialization.load_pem_public_key(
            client_ecdh_public_pem.encode('utf-8')
        )
        # Derive shared secret
        shared_secret = derive_shared_secret(server_ecdh_private_key, client_ecdh_public_key)
        # Store shared secret in Redis (base64 encoded)
        import base64
        shared_secret_b64 = base64.b64encode(shared_secret).decode('utf-8')
        redis_client.setex(f'session_secret:{session_id}', 3600, shared_secret_b64)
        return jsonify({'message': 'Shared secret established.'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to establish shared secret: {str(e)}'}), 500

@app.route('/session/secure-data', methods=['POST'])
def session_secure_data():
    """Accepts encrypted payload, decrypts using session's shared secret, and returns encrypted response."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        data = request.get_json()
        ciphertext_b64 = data.get('ciphertext')
        iv_b64 = data.get('iv')
        if not ciphertext_b64 or not iv_b64:
            return jsonify({'error': 'ciphertext and iv are required.'}), 400
        # Retrieve shared secret from Redis
        shared_secret_b64 = redis_client.get(f'session_secret:{session_id}')
        if not shared_secret_b64:
            return jsonify({'error': 'Session shared secret not found.'}), 400
        shared_secret = base64.b64decode(shared_secret_b64)
        aes_key = derive_aes_key_from_shared_secret(shared_secret)
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        # Split last 16 bytes as tag, rest as ciphertext
        if len(ciphertext) < 16:
            return jsonify({'error': 'Ciphertext too short for tag.'}), 400
        tag = ciphertext[-16:]
        ct = ciphertext[:-16]
        # Decrypt
        try:
            plaintext = aes_gcm_decrypt(ct, aes_key, iv, tag)
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
        # Demo: echo the plaintext back, uppercased
        response_plaintext = plaintext.decode('utf-8').upper().encode('utf-8')
        # Encrypt response
        response_iv = os.urandom(12)
        response_ciphertext, response_tag = aes_gcm_encrypt(response_plaintext, aes_key, response_iv)
        # Append tag to ciphertext and return as one field
        resp_full_ciphertext = response_ciphertext + response_tag
        return jsonify({
            'ciphertext': base64.b64encode(resp_full_ciphertext).decode('utf-8'),
            'iv': base64.b64encode(response_iv).decode('utf-8')
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to process secure data: {str(e)}'}), 500

@app.cli.command('create-db')
def create_db():
    """Create database tables."""
    with app.app_context():
        db.create_all()
    print('Database tables created.')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)