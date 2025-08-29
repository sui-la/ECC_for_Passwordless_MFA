import re
import json
import base64
from typing import Dict, Any, Optional, List, Union
from flask import request, jsonify
from functools import wraps
import logging

# Try to import email-validator, fallback to basic validation if not available
try:
    from email_validator import validate_email, EmailNotValidError
    EMAIL_VALIDATOR_AVAILABLE = True
except ImportError:
    EMAIL_VALIDATOR_AVAILABLE = False

logger = logging.getLogger(__name__)

from .unified_error_handler import ValidationError

class InputValidator:
    """Comprehensive input validation for the ECC MFA system."""
    
    # Regex patterns for validation
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    DEVICE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\s\-_\.\(\)]{1,100}$')
    UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    
    # Maximum lengths
    MAX_EMAIL_LENGTH = 255
    MAX_DEVICE_NAME_LENGTH = 100
    MAX_PUBLIC_KEY_LENGTH = 10000
    MAX_SIGNATURE_LENGTH = 1000
    MAX_NONCE_LENGTH = 100
    MAX_SESSION_ID_LENGTH = 36
    
    @staticmethod
    def validate_email(email: str) -> str:
        """
        Validate and sanitize email address.
        
        Args:
            email: Email address to validate
            
        Returns:
            str: Normalized email address
            
        Raises:
            ValidationError: If email is invalid
        """
        if not email or not isinstance(email, str):
            raise ValidationError("Email is required and must be a string", field='email', value=email)
        
        email = email.strip().lower()
        
        if len(email) > InputValidator.MAX_EMAIL_LENGTH:
            raise ValidationError(f"Email too long (max {InputValidator.MAX_EMAIL_LENGTH} characters)", field='email', value=email)
        
        if not InputValidator.EMAIL_PATTERN.match(email):
            raise ValidationError("Invalid email format", field='email', value=email)
        
        try:
            if EMAIL_VALIDATOR_AVAILABLE:
                # Use email-validator for additional validation
                validated_email = validate_email(email)
                return validated_email.normalized
            else:
                # Basic email validation fallback
                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                    raise ValidationError("Invalid email format")
                return email
        except EmailNotValidError as e:
            raise ValidationError(f"Invalid email: {str(e)}")
    
    @staticmethod
    def validate_device_name(device_name: str) -> str:
        """
        Validate and sanitize device name.
        
        Args:
            device_name: Device name to validate
            
        Returns:
            str: Sanitized device name
            
        Raises:
            ValidationError: If device name is invalid
        """
        if not device_name or not isinstance(device_name, str):
            raise ValidationError("Device name is required and must be a string")
        
        device_name = device_name.strip()
        
        if len(device_name) > InputValidator.MAX_DEVICE_NAME_LENGTH:
            raise ValidationError(f"Device name too long (max {InputValidator.MAX_DEVICE_NAME_LENGTH} characters)")
        
        if not InputValidator.DEVICE_NAME_PATTERN.match(device_name):
            raise ValidationError("Device name contains invalid characters")
        
        return device_name
    
    @staticmethod
    def validate_public_key(public_key_pem: str) -> str:
        """
        Validate public key in PEM format.
        
        Args:
            public_key_pem: Public key in PEM format
            
        Returns:
            str: Validated public key
            
        Raises:
            ValidationError: If public key is invalid
        """
        if not public_key_pem or not isinstance(public_key_pem, str):
            raise ValidationError("Public key is required and must be a string")
        
        if len(public_key_pem) > InputValidator.MAX_PUBLIC_KEY_LENGTH:
            raise ValidationError(f"Public key too long (max {InputValidator.MAX_PUBLIC_KEY_LENGTH} characters)")
        
        # Check PEM format
        if not public_key_pem.startswith('-----BEGIN PUBLIC KEY-----'):
            raise ValidationError("Public key must be in PEM format")
        
        if not public_key_pem.endswith('-----END PUBLIC KEY-----'):
            raise ValidationError("Public key must be in PEM format")
        
        # Validate base64 content
        try:
            lines = public_key_pem.strip().split('\n')
            if len(lines) < 3:
                raise ValidationError("Invalid PEM format")
            
            # Extract base64 content
            base64_content = ''.join(lines[1:-1])
            if not InputValidator.BASE64_PATTERN.match(base64_content):
                raise ValidationError("Invalid base64 content in PEM")
            
            # Try to decode to ensure it's valid
            base64.b64decode(base64_content)
            
        except Exception as e:
            raise ValidationError(f"Invalid public key format: {str(e)}")
        
        return public_key_pem
    
    @staticmethod
    def validate_signature(signature: str) -> str:
        """
        Validate ECDSA signature in base64 format.
        
        Args:
            signature: Base64 encoded signature
            
        Returns:
            str: Validated signature
            
        Raises:
            ValidationError: If signature is invalid
        """
        if not signature or not isinstance(signature, str):
            raise ValidationError("Signature is required and must be a string")
        
        if len(signature) > InputValidator.MAX_SIGNATURE_LENGTH:
            raise ValidationError(f"Signature too long (max {InputValidator.MAX_SIGNATURE_LENGTH} characters)")
        
        if not InputValidator.BASE64_PATTERN.match(signature):
            raise ValidationError("Invalid base64 format in signature")
        
        try:
            # Try to decode to ensure it's valid
            decoded = base64.b64decode(signature)
            if len(decoded) != 64:  # ECDSA signature should be 64 bytes (32 + 32)
                raise ValidationError("Invalid signature length")
        except Exception as e:
            raise ValidationError(f"Invalid signature format: {str(e)}")
        
        return signature
    
    @staticmethod
    def validate_nonce(nonce: str) -> str:
        """
        Validate nonce/challenge string.
        
        Args:
            nonce: Nonce string to validate
            
        Returns:
            str: Validated nonce
            
        Raises:
            ValidationError: If nonce is invalid
        """
        if not nonce or not isinstance(nonce, str):
            raise ValidationError("Nonce is required and must be a string")
        
        if len(nonce) > InputValidator.MAX_NONCE_LENGTH:
            raise ValidationError(f"Nonce too long (max {InputValidator.MAX_NONCE_LENGTH} characters)")
        
        # Nonce should be alphanumeric
        if not re.match(r'^[a-zA-Z0-9]+$', nonce):
            raise ValidationError("Nonce contains invalid characters")
        
        return nonce
    
    @staticmethod
    def validate_uuid(uuid_str: str) -> str:
        """
        Validate UUID format.
        
        Args:
            uuid_str: UUID string to validate
            
        Returns:
            str: Validated UUID
            
        Raises:
            ValidationError: If UUID is invalid
        """
        if not uuid_str or not isinstance(uuid_str, str):
            raise ValidationError("UUID is required and must be a string")
        
        if not InputValidator.UUID_PATTERN.match(uuid_str):
            raise ValidationError("Invalid UUID format")
        
        return uuid_str
    
    @staticmethod
    def validate_device_id(device_id: str) -> str:
        """
        Validate and sanitize device ID (UUID format).
        
        Args:
            device_id: Device ID to validate
            
        Returns:
            str: Normalized device ID
            
        Raises:
            ValidationError: If device ID is invalid
        """
        return InputValidator.validate_uuid(device_id)
    
    @staticmethod
    def validate_session_id(session_id: str) -> str:
        """
        Validate session ID.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            str: Validated session ID
            
        Raises:
            ValidationError: If session ID is invalid
        """
        if not session_id or not isinstance(session_id, str):
            raise ValidationError("Session ID is required and must be a string")
        
        if len(session_id) > InputValidator.MAX_SESSION_ID_LENGTH:
            raise ValidationError(f"Session ID too long (max {InputValidator.MAX_SESSION_ID_LENGTH} characters)")
        
        # Session ID should be alphanumeric with optional hyphens
        if not re.match(r'^[a-zA-Z0-9\-]+$', session_id):
            raise ValidationError("Session ID contains invalid characters")
        
        return session_id
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """
        Sanitize string input by removing potentially dangerous characters.
        
        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            
        Returns:
            str: Sanitized string
        """
        if not isinstance(value, str):
            raise ValidationError("Value must be a string")
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in value if ord(char) >= 32)
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    @staticmethod
    def validate_json_payload(data: Dict[str, Any], required_fields: List[str], 
                            optional_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Validate JSON payload structure and content.
        
        Args:
            data: JSON data to validate
            required_fields: List of required field names
            optional_fields: Dict of optional fields with their validators
            
        Returns:
            Dict: Validated data
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(data, dict):
            raise ValidationError("Request body must be JSON object")
        
        validated_data = {}
        
        # Check required fields
        for field in required_fields:
            if field not in data:
                raise ValidationError(f"Required field '{field}' is missing")
            
            if data[field] is None:
                raise ValidationError(f"Required field '{field}' cannot be null")
            
            # Add required fields to validated_data
            validated_data[field] = data[field]
        
        # Validate optional fields
        if optional_fields and isinstance(optional_fields, dict):
            for field, validator in optional_fields.items():
                if field in data and data[field] is not None:
                    try:
                        validated_data[field] = validator(data[field])
                    except Exception as e:
                        raise ValidationError(f"Invalid value for field '{field}': {str(e)}")
        
        return validated_data

def validate_request_schema(required_fields: List[str], 
                          optional_fields: Optional[Dict[str, Any]] = None):
    """
    Decorator for validating request schema.
    
    Args:
        required_fields: List of required field names
        optional_fields: Dict of optional fields with their validators
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip validation for OPTIONS requests (CORS preflight)
            if request.method == 'OPTIONS':
                return f(*args, **kwargs)
            
            try:
                if not request.is_json:
                    return jsonify({'error': 'Content-Type must be application/json'}), 400
                
                data = request.get_json()
                if data is None:
                    return jsonify({'error': 'Invalid JSON payload'}), 400
                
                # Validate the payload
                validated_data = InputValidator.validate_json_payload(
                    data, required_fields, optional_fields
                )
                
                # Add validated data to request context
                request.validated_data = validated_data
                
                return f(*args, **kwargs)
                
            except ValidationError as e:
                # Let the global error handler deal with it
                raise e
            except Exception as e:
                logger.error(f"Unexpected validation error: {str(e)}")
                # In case of validation failure, continue without validation
                logger.warning("Continuing without validation due to error")
                return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def sanitize_inputs():
    """
    Decorator for sanitizing request inputs.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Sanitize query parameters
                if request.args:
                    for key, value in request.args.items():
                        if isinstance(value, str):
                            request.args[key] = InputValidator.sanitize_string(value, 100)
                
                # Sanitize form data
                if request.form:
                    for key, value in request.form.items():
                        if isinstance(value, str):
                            request.form[key] = InputValidator.sanitize_string(value, 1000)
                
                return f(*args, **kwargs)
                
            except ValidationError as e:
                # Let the global error handler deal with it
                raise e
            except Exception as e:
                logger.error(f"Unexpected sanitization error: {str(e)}")
                # In case of sanitization failure, continue without sanitization
                logger.warning("Continuing without sanitization due to error")
                return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Predefined validation schemas for common endpoints
REGISTRATION_SCHEMA = {
    'required_fields': ['email', 'public_key_pem'],
    'optional_fields': {
        'device_name': InputValidator.validate_device_name
    }
}

AUTH_CHALLENGE_SCHEMA = {
    'required_fields': ['email'],
    'optional_fields': {}
}

AUTH_VERIFY_SCHEMA = {
    'required_fields': ['email', 'signature'],
    'optional_fields': {
        'device_id': InputValidator.validate_device_id
    }
}

DEVICE_ADD_SCHEMA = {
    'required_fields': ['public_key_pem'],
    'optional_fields': {
        'device_name': InputValidator.validate_device_name
    }
}

RECOVERY_SCHEMA = {
    'required_fields': ['email'],
    'optional_fields': {}
}

RECOVERY_COMPLETE_SCHEMA = {
    'required_fields': ['recovery_token', 'public_key_pem'],
    'optional_fields': {
        'device_name': InputValidator.validate_device_name
    }
} 