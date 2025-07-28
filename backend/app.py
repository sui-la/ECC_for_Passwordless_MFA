from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
from database.models import db
from database.db_operations import (
    add_user, get_user_by_email, add_device, get_device_by_public_key,
    update_device_last_used, get_user_devices, remove_device, add_session, add_auth_log
)
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
from flask_talisman import Talisman
from database.models import Device

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
CORS(app, 
     origins=["http://localhost:3000"], 
     supports_credentials=True,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
     expose_headers=["Content-Type", "Authorization"]
)
app.config.from_object(Config)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)
db.init_app(app)

# Add Flask-Talisman for security headers and HTTPS enforcement
Talisman(app, 
         content_security_policy=None,
         force_https=False,  # Disable HTTPS enforcement for testing
         strict_transport_security=False,  # Disable HSTS for testing
         frame_options='DENY')  # Set X-Frame-Options to DENY

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
    device_name = data.get('device_name', 'Unknown Device')
    if not email or not public_key_pem:
        return jsonify({'error': 'Email and public_key_pem are required.'}), 400
    user = get_user_by_email(email)
    if user:
        # Check if this device is already registered
        existing_device = get_device_by_public_key(public_key_pem.encode('utf-8'))
        if existing_device and existing_device.user_id == user.user_id:
            # Update the device's last_used timestamp
            update_device_last_used(existing_device.device_id)
            send_notification_email(
                subject="Your device was re-authenticated",
                recipient=email,
                body=f"Your device '{existing_device.device_name}' was re-authenticated. If this wasn't you, please contact support."
            )
            return jsonify({'message': 'Device re-authenticated successfully.'}), 200
        else:
            # Add a new device for this user
            add_device(user.user_id, public_key_pem.encode('utf-8'), device_name)
            send_notification_email(
                subject="New device registered",
                recipient=email,
                body=f"A new device '{device_name}' was registered to your account. If this wasn't you, please contact support."
            )
            return jsonify({'message': 'New device registered successfully.'}), 200
    # Create new user with first device
    add_user(email, public_key_pem.encode('utf-8'), device_name)
    send_notification_email(
        subject="Welcome to ECC Passwordless MFA!",
        recipient=email,
        body="Thank you for registering. Your account is now active."
    )
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
            print("Signature decoded as base64:", binascii.hexlify(signature_bytes))
        except Exception as e:
            print("Base64 decode failed:", e)
            return jsonify({'error': 'Signature decode failed.'}), 400

        print("Signature bytes length:", len(signature_bytes))
        print("Nonce (utf-8):", nonce.encode('utf-8'))
        print("Nonce (raw):", nonce)
        
        # Find the device by public key (we need to get the public key from the request)
        # For now, we'll need to modify the frontend to send the public key or device identifier
        # For this implementation, let's assume we can identify the device from the user's devices
        devices = get_user_devices(user.user_id)
        if not devices:
            print("No devices found for user")
            return jsonify({'error': 'No devices found for user.'}), 404
        
        # TODO: In a production system, you would:
        # 1. Send device fingerprint from frontend
        # 2. Match it with stored device fingerprints
        # 3. Or send the specific device_id for authentication
        # For now, use the first active device (in a real implementation, you'd identify the specific device)
        device = devices[0]
        print("Using device:", device.device_name)
        
        print("Public key PEM:", device.public_key)
        public_key = serialization.load_pem_public_key(device.public_key)
        print("Verifying signature...")
        der_sig = raw_to_der(signature_bytes)
        public_key.verify(der_sig, nonce.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        print("Signature verification succeeded.")
        # Update device last_used
        update_device_last_used(device.device_id)
        # Update user last_login
        user.last_login = datetime.utcnow()
        db.session.commit()
        # Create a new session
        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=1)
        session = add_session(session_id, user.user_id, device.device_id, expires_at)
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
        add_auth_log(
            user_id=user.user_id,
            device_id=device.device_id,
            event_type='login_success',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        payload = {
            'user_id': user.user_id,
            'email': user.email,
            'device_id': device.device_id,
            'exp': expires_at,
            'session_id': session_id
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        redis_client.delete(f'auth_nonce:{email}')
        print("==== DEBUG END ====")
        # Send login notification email
        try:
            send_notification_email(
                subject="Login Alert",
                recipient=email,
                body="You have successfully logged in to ECC MFA."
            )
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
        device_id = device.device_id if 'device' in locals() and device else None
        try:
            add_auth_log(
                user_id=user_id,
                device_id=device_id,
                event_type='login_failure',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=False
            )
        except Exception as log_err:
            print(f"Failed to log authentication failure: {log_err}")
        print("==== DEBUG END ====")
        return jsonify({'error': f'Authentication failed: {str(e)}'}), 500
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

@app.route('/devices', methods=['GET'])
def get_devices():
    """Get all devices for the authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        devices = get_user_devices(user_id)
        device_list = []
        for device in devices:
            device_list.append({
                'device_id': device.device_id,
                'device_name': device.device_name,
                'created_at': device.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if device.created_at else None,
                'last_used': device.last_used.strftime('%Y-%m-%d %H:%M:%S UTC') if device.last_used else None,
                'is_active': device.is_active
            })
        
        return jsonify({'devices': device_list}), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        print(f"Get devices error: {str(e)}")
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/devices', methods=['POST'])
def add_new_device():
    """Add a new device for the authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        data = request.get_json()
        public_key_pem = data.get('public_key_pem')
        device_name = data.get('device_name', 'Unknown Device')
        
        if not public_key_pem:
            return jsonify({'error': 'public_key_pem is required.'}), 400
        
        # Check if this device is already registered for this user
        existing_device = get_device_by_public_key(public_key_pem.encode('utf-8'))
        if existing_device and existing_device.user_id == user_id:
            return jsonify({'error': 'Device already registered.'}), 400
        
        # Add the new device
        device = add_device(user_id, public_key_pem.encode('utf-8'), device_name)
        
        return jsonify({
            'message': 'Device added successfully.',
            'device_id': device.device_id,
            'device_name': device.device_name
        }), 201
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        print(f"Add device error: {str(e)}")
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/devices/<device_id>', methods=['DELETE'])
def remove_user_device(device_id):
    """Remove a device for the authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        # Remove the device (soft delete)
        success = remove_device(device_id, user_id)
        if not success:
            return jsonify({'error': 'Device not found or not authorized.'}), 404
        
        return jsonify({'message': 'Device removed successfully.'}), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        print(f"Remove device error: {str(e)}")
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/devices/<device_id>/public-key', methods=['GET'])
def get_device_public_key(device_id):
    """Get the public key for a specific device."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        # Get the device and verify it belongs to the user
        device = Device.query.filter_by(device_id=device_id, user_id=user_id, is_active=True).first()
        if not device:
            return jsonify({'error': 'Device not found or not authorized.'}), 404
        
        # Return the public key in PEM format
        public_key_pem = device.public_key.decode('utf-8')
        return jsonify({
            'device_id': device.device_id,
            'device_name': device.device_name,
            'public_key_pem': public_key_pem
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        print(f"Get device public key error: {str(e)}")
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/recovery/initiate', methods=['POST'])
def initiate_recovery():
    """Initiate account recovery process by sending recovery email."""
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required.'}), 400
    
    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    
    # Generate recovery token
    recovery_token = str(uuid.uuid4())
    recovery_expires = datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
    
    # Store recovery token in Redis
    redis_client.setex(f'recovery_token:{recovery_token}', 86400, user.user_id)
    
    # Send recovery email
    recovery_url = f"http://localhost:3000/recovery?token={recovery_token}"
    try:
        send_notification_email(
            subject="Account Recovery Request",
            recipient=email,
            body=f"""You have requested to recover your ECC Passwordless MFA account.

To proceed with account recovery, click the following link:
{recovery_url}

This link will expire in 24 hours. If you didn't request this recovery, please ignore this email.

For security reasons, this recovery process will require you to:
1. Verify your email address
2. Generate a new backup key
3. Re-authenticate with your new key

If you have any questions, please contact support."""
        )
        return jsonify({'message': 'Recovery email sent successfully.'}), 200
    except Exception as e:
        print(f"Failed to send recovery email: {e}")
        return jsonify({'error': 'Failed to send recovery email.'}), 500

@app.route('/recovery/verify-token', methods=['POST'])
def verify_recovery_token():
    """Verify recovery token and return user info."""
    data = request.get_json()
    recovery_token = data.get('recovery_token')
    if not recovery_token:
        return jsonify({'error': 'Recovery token is required.'}), 400
    
    # Check if token exists and is valid
    user_id = redis_client.get(f'recovery_token:{recovery_token}')
    if not user_id:
        return jsonify({'error': 'Invalid or expired recovery token.'}), 400
    
    user = get_user_by_email(user_id) if user_id else None
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    
    return jsonify({
        'email': user.email,
        'user_id': user.user_id,
        'recovery_token': recovery_token
    }), 200

@app.route('/recovery/complete', methods=['POST'])
def complete_recovery():
    """Complete account recovery by registering new backup key."""
    data = request.get_json()
    recovery_token = data.get('recovery_token')
    public_key_pem = data.get('public_key_pem')
    device_name = data.get('device_name', 'Recovery Device')
    
    if not recovery_token or not public_key_pem:
        return jsonify({'error': 'Recovery token and public key are required.'}), 400
    
    # Verify recovery token
    user_id = redis_client.get(f'recovery_token:{recovery_token}')
    if not user_id:
        return jsonify({'error': 'Invalid or expired recovery token.'}), 400
    
    user = get_user_by_email(user_id) if user_id else None
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    
    try:
        # Add new recovery device
        add_device(user.user_id, public_key_pem.encode('utf-8'), device_name)
        
        # Delete recovery token
        redis_client.delete(f'recovery_token:{recovery_token}')
        
        # Send recovery completion email
        send_notification_email(
            subject="Account Recovery Completed",
            recipient=user.email,
            body=f"""Your account recovery has been completed successfully.

A new device '{device_name}' has been registered to your account. You can now use this device to authenticate.

For security, we recommend:
1. Reviewing your registered devices
2. Removing any old devices you no longer use
3. Setting up additional backup devices

If you didn't complete this recovery, please contact support immediately."""
        )
        
        return jsonify({'message': 'Account recovery completed successfully.'}), 200
    except Exception as e:
        print(f"Recovery completion error: {e}")
        return jsonify({'error': 'Failed to complete recovery.'}), 500

@app.route('/backup/generate', methods=['POST'])
def generate_backup_key():
    """Generate a backup key for the authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        # Generate backup key pair
        from crypto.ecc_operations import generate_private_key, get_public_key, serialize_public_key
        backup_private_key = generate_private_key()
        backup_public_key = get_public_key(backup_private_key)
        
        # Serialize keys
        private_key_pem = backup_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = serialize_public_key(backup_public_key)
        
        # Store backup public key in database
        backup_device_name = f"Backup Key ({datetime.utcnow().strftime('%Y-%m-%d %H:%M')})"
        # Ensure public_key_pem is bytes before storing
        if isinstance(public_key_pem, str):
            public_key_bytes = public_key_pem.encode('utf-8')
        else:
            public_key_bytes = public_key_pem
        add_device(user_id, public_key_bytes, backup_device_name)
        
        return jsonify({
            'private_key_pem': private_key_pem.decode('utf-8'),
            'public_key_pem': public_key_pem.decode('utf-8'),
            'backup_id': str(uuid.uuid4()),
            'created_at': datetime.utcnow().isoformat()
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        print(f"Backup key generation error: {e}")
        return jsonify({'error': 'Failed to generate backup key.'}), 500

@app.cli.command('create-db')
def create_db():
    """Create database tables."""
    with app.app_context():
        db.create_all()
    print('Database tables created.')

@app.cli.command('migrate-db')
def migrate_db():
    """Migrate database schema."""
    with app.app_context():
        try:
            # Drop all tables and recreate them (for development)
            db.drop_all()
            db.create_all()
            print('Database migrated successfully.')
        except Exception as e:
            print(f'Migration failed: {e}')
            print('You may need to manually update your database schema.')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)