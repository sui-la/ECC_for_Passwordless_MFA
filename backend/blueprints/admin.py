"""
Admin Blueprint for ECC Passwordless MFA.
Handles CLI commands and admin operations.
"""

from flask import Blueprint, jsonify, request, current_app
from database.models import db
from database.db_operations import get_user_by_email
from utils.validation import InputValidator
from utils.rate_limiting import get_client_identifier
from utils.security_headers import validate_api_security
from utils.logging_middleware import log_authentication_attempt
from utils.email_utils import send_notification_email
from utils.redis_utils import get_redis_client, generate_verification_code
from datetime import datetime, timedelta

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')



@admin_bp.route('/profile', methods=['GET'])
def get_profile():
    """Get user profile information."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401

    token = auth_header.split(' ')[1]
    try:
        import jwt
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
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

@admin_bp.route('/email/send-verification', methods=['POST', 'OPTIONS'])
def send_email_verification():
    """Send a 6-digit verification code to the user's email."""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    try:
        data = request.get_json()
        email = InputValidator.validate_email(data['email'])
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        redis_client = get_redis_client()
        
        # Check if user exists
        user = get_user_by_email(email)
        if not user:
            return jsonify({'error': 'User not found.'}), 404
        
        # Generate 6-digit verification code
        verification_code = generate_verification_code()
        
        # Store verification code in Redis with 10-minute expiry
        redis_client.setex(f'email_verification:{email}', 300, verification_code)
        
        # Send verification email
        send_notification_email(
            subject="Your ECC Passwordless MFA Verification Code",
            recipient=email,
            body=f"""Your verification code is: {verification_code}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
ECC Passwordless MFA Team"""
        )
        
        return jsonify({'message': 'Verification code sent successfully.'}), 200
        
    except Exception as e:
        raise e

@admin_bp.route('/email/verify-code', methods=['POST', 'OPTIONS'])
def verify_email_code():
    """Verify the 6-digit code sent to the user's email and automatically authenticate."""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    try:
        data = request.get_json()
        email = InputValidator.validate_email(data['email'])
        verification_code = data['verification_code']
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        redis_client = get_redis_client()
        
        # Check if user exists
        user = get_user_by_email(email)
        if not user:
            return jsonify({'error': 'User not found.'}), 404
        
        # Get stored verification code from Redis
        stored_code = redis_client.get(f'email_verification:{email}')
        if not stored_code:
            return jsonify({'error': 'Verification code expired or not found.'}), 400
        
        # Handle Redis response (could be bytes or string depending on Redis configuration)
        if isinstance(stored_code, bytes):
            stored_code = stored_code.decode('utf-8')
        
        # Verify the code
        if verification_code != stored_code:
            return jsonify({'error': 'Invalid verification code.'}), 400
        
        # Code is valid - remove it from Redis and mark user as verified
        redis_client.delete(f'email_verification:{email}')
        
        # Mark user as verified in database
        from database.db_operations import mark_user_email_verified
        mark_user_email_verified(user.user_id)
        
        # Store verification status in Redis for 24 hours
        redis_client.setex(f'email_verified:{email}', 300, 'true')
        
        # AUTOMATIC AUTHENTICATION AFTER EMAIL VERIFICATION
        # Get user devices for authentication
        from database.db_operations import get_user_devices, update_device_last_used, add_session
        devices = get_user_devices(user.user_id)
        if not devices:
            return jsonify({'error': 'No devices found for user.'}), 404
        
        # Use the first available device for authentication
        device = devices[0]
        
        # Update device and user
        update_device_last_used(device.device_id)
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Create session
        import uuid
        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        session = add_session(session_id, user.user_id, device.device_id, expires_at)
        
        # Enhanced ECDH Key Exchange with perfect forward secrecy
        from crypto.ecdh_handler import generate_ephemeral_keypair, serialize_public_key
        server_ecdh_private_key, server_ecdh_public_key = generate_ephemeral_keypair()
        server_ecdh_public_pem = serialize_public_key(server_ecdh_public_key)
        
        # Store server's ECDH private key in Redis
        from cryptography.hazmat.primitives import serialization
        server_ecdh_private_pem = server_ecdh_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        redis_client.setex(f'ecdh_privkey:{session_id}', 300, server_ecdh_private_pem.decode('utf-8'))
        
        # Log successful authentication
        from database.db_operations import add_auth_log
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
        import jwt
        payload = {
            'user_id': user.user_id,
            'email': user.email,
            'device_id': device.device_id,
            'exp': expires_at,
            'session_id': session_id
        }
        token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        
        # Send notification email about successful login
        try:
            send_notification_email(
                subject="Login Alert",
                recipient=email,
                body="You have successfully logged in to ECC MFA after email verification."
            )
        except Exception as email_error:
            # Log email error but don't fail the authentication
            print(f"Failed to send login notification email: {email_error}")
        
        return jsonify({
            'message': 'Email verification and authentication successful!',
            'token': token,
            'server_ecdh_public_key': server_ecdh_public_pem,
            'session_id': session_id
        }), 200
        
    except Exception as e:
        raise e

# CLI Commands
@admin_bp.cli.command('create-db')
def create_db():
    """Create database tables."""
    with current_app.app_context():
        try:
            from database.db_operations import reset_database
            reset_database()
            print('Database tables created.')
        except Exception as e:
            print(f'Error creating database: {e}')

@admin_bp.cli.command('migrate-db')
def migrate_db():
    """Migrate database schema."""
    with current_app.app_context():
        try:
            # Drop all tables and recreate them (for development)
            db.drop_all()
            db.create_all()
            print('Database migrated successfully.')
        except Exception as e:
            print(f'Migration failed: {e}')
            print('You may need to manually update your database schema.')

@admin_bp.cli.command('clear-db')
def clear_db():
    """Clear all data from database tables."""
    with current_app.app_context():
        try:
            from database.db_operations import clear_all_data, get_database_stats
            
            print('Clearing all data from database...')
            
            # Use the function from db_operations
            clear_all_data()
            
            # Get stats after clearing
            stats = get_database_stats()
            
            print('✓ All data cleared successfully!')
            print(f'  - Users: {stats["users"]}')
            print(f'  - Devices: {stats["devices"]}')
            print(f'  - Sessions: {stats["sessions"]}')
            print(f'  - Auth logs: {stats["auth_logs"]}')
            
        except Exception as e:
            print(f'Error clearing database: {e}')

@admin_bp.cli.command('db-stats')
def db_stats():
    """Show database statistics."""
    with current_app.app_context():
        try:
            from database.db_operations import get_database_stats
            
            stats = get_database_stats()
            
            print('Database Statistics:')
            print(f'  - Users: {stats["users"]}')
            print(f'  - Devices: {stats["devices"]}')
            print(f'  - Sessions: {stats["sessions"]}')
            print(f'  - Auth logs: {stats["auth_logs"]}')
            
        except Exception as e:
            print(f'Error getting database stats: {e}')
