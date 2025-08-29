"""
Devices Blueprint for ECC Passwordless MFA.
Handles device management operations.
"""

from flask import Blueprint, jsonify, request, current_app
from database.db_operations import (
    get_user_devices, add_device, remove_device, get_device_by_public_key
)
from database.models import Device
from utils.validation import (
    validate_request_schema, sanitize_inputs, InputValidator,
    DEVICE_ADD_SCHEMA
)
from utils.rate_limiting import auth_rate_limit, get_client_identifier
from utils.security_headers import validate_api_security
from utils.logging_middleware import log_device_management
import jwt

devices_bp = Blueprint('devices', __name__, url_prefix='/devices')

@devices_bp.route('', methods=['GET', 'OPTIONS'])
def get_devices():
    """Get all devices for the authenticated user."""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
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
        return jsonify({'error': 'Internal server error.'}), 500

@devices_bp.route('', methods=['POST', 'OPTIONS'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=['public_key_pem'],
    optional_fields={
        'device_name': InputValidator.validate_device_name
    }
)
@sanitize_inputs()
@validate_api_security()
def add_new_device():
    """Add a new device for the authenticated user."""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        email = payload.get('email')  # Extract email from JWT token
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
        
        # Log device addition
        log_device_management('add', user_id, device.device_id, email=email, device_name=device_name, ip_address=request.remote_addr)
        
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
        return jsonify({'error': 'Internal server error.'}), 500

@devices_bp.route('/<device_id>', methods=['DELETE', 'OPTIONS'])
def remove_user_device(device_id):
    """Remove a device for the authenticated user."""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        email = payload.get('email')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        # Remove the device (soft delete)
        success = remove_device(device_id, user_id)
        if not success:
            return jsonify({'error': 'Device not found or not authorized.'}), 404
        
        # Log device removal
        log_device_management('remove', user_id, device_id, email=email, ip_address=request.remote_addr)
        
        return jsonify({'message': 'Device removed successfully.'}), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        return jsonify({'error': 'Internal server error.'}), 500

@devices_bp.route('<device_id>/public-key', methods=['GET', 'OPTIONS'])
def get_device_public_key(device_id):
    """Get the public key for a specific device."""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        # Get the device and verify it belongs to the user
        device = Device.query.filter_by(device_id=device_id, user_id=user_id, is_active=True).first()
        if not device:
            return jsonify({'error': 'Device not found or not authorized.'}), 404
        
        # Return the public key in PEM format
        if isinstance(device.public_key, bytes):
            public_key_pem = device.public_key.decode('utf-8')
        else:
            public_key_pem = device.public_key
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
        return jsonify({'error': 'Internal server error.'}), 500
