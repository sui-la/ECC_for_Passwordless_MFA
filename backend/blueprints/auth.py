"""
Authentication Blueprint for ECC Passwordless MFA.
Handles user registration, authentication challenges, and verification.
"""

from flask import Blueprint, jsonify, request, current_app
from database.db_operations import (
    add_user, get_user_by_email, update_device_last_used, add_session, add_auth_log
)
from database.models import db
from utils.security import generate_nonce
from utils.validation import (
    validate_request_schema, sanitize_inputs, InputValidator,
    REGISTRATION_SCHEMA, AUTH_CHALLENGE_SCHEMA, AUTH_VERIFY_SCHEMA
)
from utils.rate_limiting import (
    auth_rate_limit, registration_rate_limit, get_client_identifier,
    get_advanced_rate_limiter
)
from utils.security_headers import validate_api_security
from utils.logging_middleware import log_authentication_attempt, log_user_registration
from crypto.ecdh_handler import (
    generate_ephemeral_keypair, serialize_public_key
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import jwt
import uuid
import base64
from datetime import datetime, timedelta
from utils.email_utils import send_notification_email
from utils.redis_utils import get_redis_client, generate_verification_code

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/register', methods=['POST', 'OPTIONS'])
@registration_rate_limit()
@validate_request_schema(
    required_fields=REGISTRATION_SCHEMA['required_fields'],
    optional_fields=REGISTRATION_SCHEMA['optional_fields']
)
@sanitize_inputs()
@validate_api_security()
def register():
    """Register a new user (first-time registration only)."""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    try:
        # Get validated data from request context
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        public_key_pem = InputValidator.validate_public_key(data['public_key_pem'])
        device_name = data.get('device_name', 'Unknown Device')
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        redis_client = get_redis_client()
        advanced_rate_limiter = get_advanced_rate_limiter()
        
        # Check if user already exists
        user = get_user_by_email(email)
        if user:
            # SECURITY FIX: Prevent existing users from registering
            # Record failure for rate limiting
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({
                'error': 'User already registered.',
                'message': 'An account with this email already exists. Please use the authentication flow to sign in.',
                'code': 'USER_ALREADY_EXISTS'
            }), 409
        else:
            # Create new user with first device
            user_id, device_id = add_user(email, public_key_pem.encode('utf-8'), device_name)
            
            # Generate and send verification code for first-time users
            verification_code = generate_verification_code()
            redis_client.setex(f'email_verification:{email}', 300, verification_code)
            
            send_notification_email(
                subject="Welcome to ECC Passwordless MFA! Please verify your email",
                recipient=email,
                body=f"""Welcome to ECC Passwordless MFA!

                Your verification code is: {verification_code}

                Please enter this code to complete your registration. This code will expire in 10 minutes.

                After verification, you'll be able to authenticate without needing verification codes for future logins.

                Best regards,
                ECC Passwordless MFA Team"""
            )
            
            # Log user registration
            log_user_registration(email, device_name, request.remote_addr)
            
            return jsonify({
                'message': 'User registered successfully. Please check your email for verification code.', 
                'device_id': device_id,
                'requires_verification': True
            }), 201
            
    except Exception as e:
        # Record failure for rate limiting
        client_id = get_client_identifier()
        advanced_rate_limiter = get_advanced_rate_limiter()
        advanced_rate_limiter.record_auth_failure(client_id)
        raise e

@auth_bp.route('/challenge', methods=['POST', 'OPTIONS'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=AUTH_CHALLENGE_SCHEMA['required_fields'],
    optional_fields=AUTH_CHALLENGE_SCHEMA['optional_fields']
)
@sanitize_inputs()
@validate_api_security()
def auth_challenge():
    """Generate authentication challenge for user."""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    try:
        # Get validated data from request context
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        redis_client = get_redis_client()
        advanced_rate_limiter = get_advanced_rate_limiter()
        
        user = get_user_by_email(email)
        if not user:
            # Record failure for rate limiting
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'User not found.'}), 404
        
        if not user.email_verified:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({
                'error': 'Email not verified.',
                'message': 'Please verify your email address before authenticating. Check your email for the verification code.',
                'code': 'EMAIL_NOT_VERIFIED'
            }), 403
        
        nonce = generate_nonce()
        redis_client.setex(f'auth_nonce:{email}', 300, nonce)
        
        # Log authentication attempt
        log_authentication_attempt(email, 'challenge', request.remote_addr, True)
        
        return jsonify({'nonce': nonce}), 200
        
    except Exception as e:
        # Record failure for rate limiting
        client_id = get_client_identifier()
        advanced_rate_limiter = get_advanced_rate_limiter()
        advanced_rate_limiter.record_auth_failure(client_id)
        raise e

@auth_bp.route('/verify', methods=['POST', 'OPTIONS'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=AUTH_VERIFY_SCHEMA['required_fields'],
    optional_fields=AUTH_VERIFY_SCHEMA['optional_fields']
)
@sanitize_inputs()
@validate_api_security()
def auth_verify():
    """Verify authentication signature and establish secure session."""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    try:
        # Get validated data from request context
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        signature = InputValidator.validate_signature(data['signature'])
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        redis_client = get_redis_client()
        advanced_rate_limiter = get_advanced_rate_limiter()
        
        user = get_user_by_email(email)
        if not user:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'User not found.'}), 404
        
        # SECURITY FIX: Check if user's email is verified before allowing authentication
        if not user.email_verified:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({
                'error': 'Email not verified.',
                'message': 'Please verify your email address before authenticating. Check your email for the verification code.',
                'code': 'EMAIL_NOT_VERIFIED'
            }), 403
        
        nonce = redis_client.get(f'auth_nonce:{email}')
        if not nonce:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'Challenge expired or not found.'}), 400
        
        # Handle Redis response (could be bytes or string depending on Redis configuration)
        if isinstance(nonce, bytes):
            nonce = nonce.decode('utf-8')
        
        try:
            # Decode signature
            signature_bytes = base64.b64decode(signature)
            
            # Get user devices
            from database.db_operations import get_user_devices
            devices = get_user_devices(user.user_id)
            if not devices:
                advanced_rate_limiter.record_auth_failure(client_id)
                return jsonify({'error': 'No devices found for user.'}), 404
            
            # Check if device_id was provided in the request
            device_id = data.get('device_id')
            if device_id:
                # Find the specific device
                device = next((d for d in devices if d.device_id == device_id), None)
            else:
                device = None
            
            # Try to verify signature with all devices until one works
            signature_verified = False
            working_device = None
            
            # Determine which devices to try
            devices_to_try = [device] if device else devices
            
            for i, dev in enumerate(devices_to_try):
                try:
                    # Load public key from this device
                    from crypto.ecdh_handler import deserialize_public_key
                    public_key = deserialize_public_key(dev.public_key)
                    
                    # Prepare signature for verification
                    if len(signature_bytes) == 64:
                        # Raw signature (r + s concatenated), convert to DER
                        r = int.from_bytes(signature_bytes[:32], byteorder='big')
                        s = int.from_bytes(signature_bytes[32:], byteorder='big')
                        der_sig = encode_dss_signature(r, s)
                    else:
                        # Already DER signature
                        der_sig = signature_bytes
                    
                    # Attempt verification
                    public_key.verify(der_sig, nonce.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
                    signature_verified = True
                    working_device = dev
                    break
                    
                except Exception as verify_error:
                    continue
            
            if not signature_verified:
                # Check if this is a returning user who needs email verification
                # If signature verification fails but user exists, they might need email verification
                # A first-time user would have no devices, a returning user would have devices
                is_first_time_user = len(devices) == 0
                
                if not is_first_time_user:
                    # This is a returning user - check if they have verified their email recently
                    email_verified = redis_client.get(f'email_verified:{email}')
                    # Handle Redis response (could be bytes or string)
                    if isinstance(email_verified, bytes):
                        email_verified = email_verified.decode('utf-8')
                    
                    # If email was recently verified, allow authentication even if signature fails
                    if email_verified and email_verified == 'true':
                        # Find any device for this user to use for authentication
                        if devices:
                            device = devices[0]  # Use the first available device
                            
                            # Update device and user
                            update_device_last_used(device.device_id)
                            user.last_login = datetime.utcnow()
                            db.session.commit()
                            
                            # Create session
                            session_id = str(uuid.uuid4())
                            expires_at = datetime.utcnow() + timedelta(minutes=5)  # Changed from hours=1 to minutes=5 for testing
                            session = add_session(session_id, user.user_id, device.device_id, expires_at)
                            
                            # Enhanced ECDH Key Exchange with perfect forward secrecy
                            server_ecdh_private_key, server_ecdh_public_key = generate_ephemeral_keypair()
                            server_ecdh_public_pem = serialize_public_key(server_ecdh_public_key)
                            
                            # Store server's ECDH private key in Redis
                            server_ecdh_private_pem = server_ecdh_private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                            )
                            redis_client.setex(f'ecdh_privkey:{session_id}', 300, server_ecdh_private_pem.decode('utf-8'))  # Changed from 3600 to 300 seconds (5 minutes) for testing
                            
                            # Log successful authentication
                            add_auth_log(
                                user_id=user.user_id,
                                device_id=device.device_id,
                                event_type='login_success',
                                ip_address=request.remote_addr,
                                user_agent=request.headers.get('User-Agent'),
                                success=True
                            )
                            
                            # Mark user as having a recent successful login (24 hours)
                            redis_client.setex(f'recent_login:{email}', 300, 'true')
                            
                            # Generate JWT token
                            payload = {
                                'user_id': user.user_id,
                                'email': user.email,
                                'device_id': device.device_id,
                                'exp': expires_at,
                                'session_id': session_id
                            }
                            token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
                            
                            # Clean up nonce
                            redis_client.delete(f'auth_nonce:{email}')
                            
                            # Record successful authentication
                            advanced_rate_limiter.record_auth_success(client_id)
                            
                            return jsonify({
                                'token': token, 
                                'server_ecdh_public_key': server_ecdh_public_pem,
                                'session_id': session_id
                            }), 200
                        else:
                            raise Exception("No devices found for user")
                    
                    # Only require verification if they haven't verified recently (within 24 hours)
                    # This prevents constant verification requests for legitimate users
                    if not email_verified:
                        # Check if they have a recent successful login (within 24 hours)
                        # If they do, don't require verification
                        recent_login = redis_client.get(f'recent_login:{email}')
                        
                        # Always allow email verification when signature verification fails
                        # This ensures users can still authenticate even if their keys are mismatched
                        
                        # Send verification code and require verification
                        verification_code = generate_verification_code()
                        redis_client.setex(f'email_verification:{email}', 300, verification_code)
                        
                        send_notification_email(
                            subject="Your ECC Passwordless MFA Verification Code",
                            recipient=email,
                            body=f"""Your verification code is: {verification_code}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
ECC Passwordless MFA Team"""
                        )
                        
                        return jsonify({
                            'error': 'Email verification required.',
                            'requires_verification': True,
                            'message': 'Please check your email for verification code.'
                        }), 403
                    else:
                        pass
                
                # If we reach here, either it's a first-time user or they don't need verification
                raise Exception("Signature verification failed with all available devices")
            
            # Use the working device for the rest of the authentication
            device = working_device
            
            # Update device and user
            update_device_last_used(device.device_id)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Create session
            session_id = str(uuid.uuid4())
            expires_at = datetime.utcnow() + timedelta(minutes=5)
            session = add_session(session_id, user.user_id, device.device_id, expires_at)
            
            # Enhanced ECDH Key Exchange with perfect forward secrecy
            server_ecdh_private_key, server_ecdh_public_key = generate_ephemeral_keypair()
            server_ecdh_public_pem = serialize_public_key(server_ecdh_public_key)
            
            # Store server's ECDH private key in Redis
            server_ecdh_private_pem = server_ecdh_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            redis_client.setex(f'ecdh_privkey:{session_id}', 300, server_ecdh_private_pem.decode('utf-8'))
            
            # Log successful authentication
            add_auth_log(
                user_id=user.user_id,
                device_id=device.device_id,
                event_type='login_success',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=True
            )
            
            # Mark user as having a recent successful login (24 hours)
            redis_client.setex(f'recent_login:{email}', 300, 'true')
            
            # Generate JWT token
            payload = {
                'user_id': user.user_id,
                'email': user.email,
                'device_id': device.device_id,
                'exp': expires_at,
                'session_id': session_id
            }
            token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
            
            # Clean up nonce
            redis_client.delete(f'auth_nonce:{email}')
            
            # Record successful authentication
            advanced_rate_limiter.record_auth_success(client_id)
            
            # Send notification emails
            try:
                send_notification_email(
                    subject="Login Alert",
                    recipient=email,
                    body="You have successfully logged in to ECC MFA."
                )
                send_notification_email(
                    subject="New Login to Your Account",
                    recipient=email,
                    body=f"A new login to your ECC Passwordless MFA account was detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}. If this wasn't you, please contact support."
                )
            except Exception as e:
                pass
            
            return jsonify({
                'token': token,
                'server_ecdh_public_key': server_ecdh_public_pem,
                'session_id': session_id
            }), 200
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            
            # Record authentication failure
            advanced_rate_limiter.record_auth_failure(client_id)
            
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
                pass
            
            return jsonify({'error': 'Authentication failed. Please check your credentials and try again.'}), 500
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        
        # Record failure for rate limiting
        client_id = get_client_identifier()
        advanced_rate_limiter = get_advanced_rate_limiter()
        advanced_rate_limiter.record_auth_failure(client_id)
        raise e
