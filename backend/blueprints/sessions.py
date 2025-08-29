"""
Sessions Blueprint for ECC Passwordless MFA.
Handles ECDH key exchange and secure messaging.
"""

from flask import Blueprint, jsonify, request, current_app
from database.db_operations import get_user_by_email
from crypto.ecdh_handler import (
    derive_shared_secret, generate_ephemeral_keypair, serialize_public_key
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from utils.email_utils import send_notification_email
from utils.logging_middleware import log_session_events
from utils.redis_utils import get_redis_client
import jwt
import base64
import os
import json
from datetime import datetime

sessions_bp = Blueprint('sessions', __name__, url_prefix='/session')



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

@sessions_bp.route('/ecdh', methods=['POST'])
def session_ecdh():
    """Receive client's ECDH public key, derive shared secret, and store it for the session."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        data = request.get_json()
        client_ecdh_public_pem = data.get('client_ecdh_public_key')
        if not client_ecdh_public_pem:
            return jsonify({'error': 'client_ecdh_public_key is required.'}), 400
        # Retrieve server's ECDH private key from Redis
        redis_client = get_redis_client()
        server_ecdh_private_pem = redis_client.get(f'ecdh_privkey:{session_id}')
        if not server_ecdh_private_pem:
            return jsonify({'error': 'Server ECDH private key not found or expired.'}), 400
        
        # Handle Redis response (could be bytes or string)
        if isinstance(server_ecdh_private_pem, bytes):
            server_ecdh_private_pem = server_ecdh_private_pem.decode('utf-8')
        
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
        shared_secret_b64 = base64.b64encode(shared_secret).decode('utf-8')
        redis_client.setex(f'session_secret:{session_id}', 300, shared_secret_b64)
        
        # Log session establishment
        log_session_events('ecdh_established', payload.get('user_id'), session_id, ip_address=request.remote_addr, success=True)
        
        return jsonify({'message': 'Shared secret established.'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to establish shared secret: {str(e)}'}), 500

@sessions_bp.route('/secure-data', methods=['POST'])
def session_secure_data():
    """Accepts encrypted payload, decrypts using session's shared secret, and returns encrypted response."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        data = request.get_json()
        ciphertext_b64 = data.get('ciphertext')
        iv_b64 = data.get('iv')
        if not ciphertext_b64 or not iv_b64:
            return jsonify({'error': 'ciphertext and iv are required.'}), 400
        # Retrieve shared secret from Redis
        redis_client = get_redis_client()
        shared_secret_b64 = redis_client.get(f'session_secret:{session_id}')
        if not shared_secret_b64:
            return jsonify({'error': 'Session shared secret not found.'}), 400
        
        # Handle Redis response (could be bytes or string)
        if isinstance(shared_secret_b64, bytes):
            shared_secret_b64 = shared_secret_b64.decode('utf-8')
        
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

@sessions_bp.route('/send-secure-message', methods=['POST'])
def send_secure_message():
    """Send an encrypted message to another user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        sender_user_id = payload.get('user_id')
        sender_email = payload.get('email')
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        
        data = request.get_json()
        recipient_email = data.get('recipient_email')
        encrypted_message = data.get('encrypted_message')
        message_iv = data.get('message_iv')
        message_id = data.get('message_id')  # Get message_id from frontend
        
        if not recipient_email or not encrypted_message or not message_iv or not message_id:
            return jsonify({'error': 'recipient_email, encrypted_message, message_iv, and message_id are required.'}), 400
        
        # Validate recipient email
        from utils.validation import InputValidator
        recipient_email = InputValidator.validate_email(recipient_email)
        
        # Check if recipient exists
        recipient_user = get_user_by_email(recipient_email)
        if not recipient_user:
            return jsonify({'error': 'Recipient not found.'}), 404
        
        # Check if sender is trying to send to themselves
        if sender_email == recipient_email:
            return jsonify({'error': 'Cannot send message to yourself.'}), 400
        
        # Store the encrypted message in Redis with recipient's email as key
        # The message will be encrypted with the sender's session key, so only the sender can decrypt it
        # The recipient will need to establish their own session to read it
        message_data = {
            'sender_email': sender_email,
            'sender_user_id': sender_user_id,
            'encrypted_message': encrypted_message,
            'message_iv': message_iv,
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': session_id,  # This helps identify which session encrypted the message
            'message_id': message_id # Store the message_id
        }
        
        # Store with 24-hour expiry
        message_key = f'secure_message:{recipient_email}:{message_id}' # Use message_id as part of the key
        redis_client = get_redis_client()
        redis_client.setex(message_key, 300, json.dumps(message_data))
        
        # Send notification email to recipient
        try:
            send_notification_email(
                subject="You have a new secure message",
                recipient=recipient_email,
                body=f"""You have received a new secure message from {sender_email}.

To read this message, please log in to your ECC Passwordless MFA account.

The message will be available for 24 hours.

Best regards,
ECC Passwordless MFA Team"""
            )
        except Exception as e:
            pass
            # Don't fail the whole operation if email fails
        
        # Log message sent
        log_session_events('message_sent', payload.get('user_id'), message_id, ip_address=request.remote_addr, success=True)
        
        return jsonify({
            'message': 'Secure message sent successfully.',
            'message_id': message_id
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to send secure message: {str(e)}'}), 500

@sessions_bp.route('/receive-secure-messages', methods=['GET'])
def receive_secure_messages():
    """Get all encrypted messages for the authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_email = payload.get('email')
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        
        # Get all message keys for this user
        redis_client = get_redis_client()
        message_keys = redis_client.keys(f'secure_message:{user_email}:*')
        messages = []
        
        for key in message_keys:
            message_data = redis_client.get(key)
            if message_data:
                try:
                    # Parse the stored message data using JSON
                    if isinstance(message_data, bytes):
                        message_data = message_data.decode('utf-8')
                    
                    # Try JSON first, fallback to ast.literal_eval for old format
                    try:
                        message_info = json.loads(message_data)
                    except json.JSONDecodeError:
                        import ast
                        message_info = ast.literal_eval(message_data)
                    
                    messages.append({
                        'message_id': message_info['message_id'], # Use message_id from data
                        'sender_email': message_info['sender_email'],
                        'encrypted_message': message_info['encrypted_message'],
                        'message_iv': message_info['message_iv'],
                        'timestamp': message_info['timestamp'],
                        'session_id': message_info['session_id']
                    })
                except Exception as e:
                    continue
        
        # Sort messages by timestamp (newest first)
        messages.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            'messages': messages,
            'count': len(messages)
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to retrieve secure messages: {str(e)}'}), 500

@sessions_bp.route('/delete-secure-message/<message_id>', methods=['DELETE'])
def delete_secure_message(message_id):
    """Delete a specific encrypted message."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_email = payload.get('email')
        if not user_email:
            return jsonify({'error': 'Invalid token.'}), 401
        
        # Find the message by searching through all message keys for this user
        redis_client = get_redis_client()
        message_keys = redis_client.keys(f'secure_message:{user_email}:*')
        
        for key in message_keys:
            message_data = redis_client.get(key)
            if message_data:
                try:
                    import ast
                    message_info = ast.literal_eval(message_data)
                    if message_info.get('message_id') == message_id:
                        deleted = redis_client.delete(key)
                        if deleted:
                            # Log message deletion
                            log_session_events('message_deleted', payload.get('user_id'), message_id, ip_address=request.remote_addr, success=True)
                            return jsonify({'message': 'Message deleted successfully.'}), 200
                        else:
                            return jsonify({'error': 'Failed to delete message from storage.'}), 500
                except Exception as e:
                    continue
        
        # If we get here, the message was not found
        return jsonify({'error': 'Message not found.'}), 404
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to delete message: {str(e)}'}), 500

@sessions_bp.route('/update-message-encryption/<message_id>', methods=['PUT'])
def update_message_encryption(message_id):
    """Update the encryption of an existing message (for re-encryption)."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_email = payload.get('email')
        if not user_email:
            return jsonify({'error': 'Invalid token.'}), 401
        
        data = request.get_json()
        new_encrypted_message = data.get('encrypted_message')
        new_message_iv = data.get('message_iv')
        new_message_id = data.get('new_message_id')
        
        if not new_encrypted_message or not new_message_iv or not new_message_id:
            return jsonify({'error': 'encrypted_message, message_iv, and new_message_id are required.'}), 400
        
        # Find the message by searching through all message keys for this user
        redis_client = get_redis_client()
        message_keys = redis_client.keys(f'secure_message:{user_email}:*')
        message_found = False
        
        for key in message_keys:
            message_data = redis_client.get(key)
            if message_data:
                try:
                    import ast
                    message_info = ast.literal_eval(message_data)
                    if message_info.get('message_id') == message_id:
                        # Found the message, update it
                        message_info['encrypted_message'] = new_encrypted_message
                        message_info['message_iv'] = new_message_iv
                        message_info['message_id'] = new_message_id
                        message_info['timestamp'] = datetime.utcnow().isoformat()
                        
                        # Delete old key and create new one
                        redis_client.delete(key)
                        new_key = f'secure_message:{user_email}:{new_message_id}'
                        redis_client.setex(new_key, 300, str(message_info))
                        
                        # Log message encryption update
                        log_session_events('message_encryption_updated', payload.get('user_id'), new_message_id, ip_address=request.remote_addr, success=True)
                        
                        return jsonify({
                            'message': 'Message encryption updated successfully.',
                            'new_message_id': new_message_id
                        }), 200
                except Exception as e:
                    continue
        
        # If we get here, the message was not found
        return jsonify({'error': 'Message not found.'}), 404
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to update message encryption: {str(e)}'}), 500
