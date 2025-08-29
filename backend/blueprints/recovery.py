"""
Recovery Blueprint for ECC Passwordless MFA.
Handles account recovery operations.
"""

from flask import Blueprint, jsonify, request, current_app
from database.db_operations import get_user_by_email, add_device
from utils.validation import (
    validate_request_schema, sanitize_inputs, InputValidator,
    RECOVERY_SCHEMA, RECOVERY_COMPLETE_SCHEMA
)
from utils.rate_limiting import auth_rate_limit, get_client_identifier
from utils.security_headers import validate_api_security
from utils.logging_middleware import log_authentication_attempt
from utils.email_utils import send_notification_email
from utils.redis_utils import get_redis_client
import uuid
from datetime import datetime, timedelta

recovery_bp = Blueprint('recovery', __name__, url_prefix='/recovery')



@recovery_bp.route('/initiate', methods=['POST'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=['email'],
    optional_fields=[]
)
@sanitize_inputs()
@validate_api_security()
def initiate_recovery():
    """Initiate account recovery process by sending recovery email."""
    try:
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        redis_client = get_redis_client()
        
        user = get_user_by_email(email)
        if not user:
            return jsonify({'error': 'User not found.'}), 404
        
        # Generate recovery token
        recovery_token = str(uuid.uuid4())
        recovery_expires = datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
        
        # Store recovery token in Redis with user email (not user_id)
        redis_client.setex(f'recovery_token:{recovery_token}', 86400, user.email)
        
        # Send recovery email
        recovery_url = f"http://localhost:3000/recovery?token={recovery_token}"
        send_notification_email(
            subject="Account Recovery Request",
            recipient=email,
            body=f"""You have requested to recover your ECC Passwordless MFA account.

To proceed with account recovery, click the following link:
{recovery_url}

This link will expire in 24 hours. If you didn't request this recovery, please ignore this email.

For security reasons, this recovery process will require you to:
1. Verify your email address
    2. Generate a new device key
3. Re-authenticate with your new key

If you have any questions, please contact support."""
        )
        
        # Log recovery initiation
        log_authentication_attempt(email, 'recovery_initiated', request.remote_addr, True)
        
        return jsonify({'message': 'Recovery email sent successfully.'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to initiate recovery.'}), 500

@recovery_bp.route('/verify-token', methods=['POST'])
def verify_recovery_token():
    """Verify recovery token and return user info."""
    data = request.get_json()
    recovery_token = data.get('recovery_token')
    if not recovery_token:
        return jsonify({'error': 'Recovery token is required.'}), 400
    
    # Check if token exists and is valid
    redis_client = get_redis_client()
    user_email = redis_client.get(f'recovery_token:{recovery_token}')
    if not user_email:
        return jsonify({'error': 'Invalid or expired recovery token.'}), 400
    
    # Handle Redis response (could be bytes or string)
    if isinstance(user_email, bytes):
        user_email = user_email.decode('utf-8')
    
    user = get_user_by_email(user_email) if user_email else None
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    
    return jsonify({
        'email': user.email,
        'user_id': user.user_id,
        'recovery_token': recovery_token
    }), 200

@recovery_bp.route('/complete', methods=['POST'])
def complete_recovery():
    """Complete account recovery by registering new device key."""
    data = request.get_json()
    recovery_token = data.get('recovery_token')
    public_key_pem = data.get('public_key_pem')
    device_name = data.get('device_name', 'Recovery Device')
    
    if not recovery_token or not public_key_pem:
        return jsonify({'error': 'Recovery token and public key are required.'}), 400
    
    # Verify recovery token
    redis_client = get_redis_client()
    user_email = redis_client.get(f'recovery_token:{recovery_token}')
    if not user_email:
        return jsonify({'error': 'Invalid or expired recovery token.'}), 400
    
    # Handle Redis response (could be bytes or string)
    if isinstance(user_email, bytes):
        user_email = user_email.decode('utf-8')
    
    user = get_user_by_email(user_email) if user_email else None
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    
    try:
        # Add new recovery device
        device = add_device(user.user_id, public_key_pem.encode('utf-8'), device_name)
        
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
3. Setting up additional devices

If you didn't complete this recovery, please contact support immediately."""
        )
        
        # Log recovery completion
        log_authentication_attempt(user.email, 'recovery_completed', request.remote_addr, True)
        
        return jsonify({
            'message': 'Account recovery completed successfully.',
            'device_id': device.device_id
        }), 200
    except Exception as e:
        return jsonify({'error': 'Failed to complete recovery.'}), 500
