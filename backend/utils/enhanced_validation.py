"""
Enhanced validation system for ECC Passwordless MFA.
Integrates with error handling for structured validation responses.
"""

import re
import logging
from typing import Dict, Any, List, Optional, Union
from flask import request
from .error_handler import ValidationError, ERROR_CODES

logger = logging.getLogger(__name__)

class EnhancedValidator:
    """Enhanced validation with structured error responses."""
    
    # Email validation regex
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    # Public key validation patterns
    PUBLIC_KEY_PATTERNS = {
        'ecdsa': re.compile(r'^-----BEGIN PUBLIC KEY-----\n.*\n-----END PUBLIC KEY-----\n?$', re.DOTALL),
        'pem': re.compile(r'^-----BEGIN.*-----\n.*\n-----END.*-----\n?$', re.DOTALL)
    }
    
    # Signature validation patterns
    SIGNATURE_PATTERNS = {
        'hex': re.compile(r'^[a-fA-F0-9]{128}$'),  # 64 bytes as hex
        'base64': re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    }
    
    # Device name validation
    DEVICE_NAME_REGEX = re.compile(r'^[a-zA-Z0-9\s\-_\.]{1,50}$')
    
    # Verification code validation
    VERIFICATION_CODE_REGEX = re.compile(r'^[0-9]{6}$')
    
    @staticmethod
    def validate_email(email: str, field_name: str = 'email') -> str:
        """
        Validate email format.
        
        Args:
            email: Email to validate
            field_name: Field name for error reporting
            
        Returns:
            Validated email
            
        Raises:
            ValidationError: If email is invalid
        """
        if not email:
            raise ValidationError(
                message="Email address is required",
                field=field_name,
                value=email
            )
        
        if not isinstance(email, str):
            raise ValidationError(
                message="Email must be a string",
                field=field_name,
                value=str(email)
            )
        
        email = email.strip().lower()
        
        if not EnhancedValidator.EMAIL_REGEX.match(email):
            raise ValidationError(
                message="Invalid email format",
                field=field_name,
                value=email
            )
        
        # Check for common disposable email domains
        disposable_domains = [
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org'
        ]
        
        domain = email.split('@')[1] if '@' in email else ''
        if domain in disposable_domains:
            raise ValidationError(
                message="Disposable email addresses are not allowed",
                field=field_name,
                value=email
            )
        
        return email
    
    @staticmethod
    def validate_public_key(public_key: str, field_name: str = 'public_key_pem') -> str:
        """
        Validate public key format.
        
        Args:
            public_key: Public key to validate
            field_name: Field name for error reporting
            
        Returns:
            Validated public key
            
        Raises:
            ValidationError: If public key is invalid
        """
        if not public_key:
            raise ValidationError(
                message="Public key is required",
                field=field_name,
                value=public_key
            )
        
        if not isinstance(public_key, str):
            raise ValidationError(
                message="Public key must be a string",
                field=field_name,
                value=str(public_key)
            )
        
        public_key = public_key.strip()
        
        # Check if it's a valid PEM format
        if not any(pattern.match(public_key) for pattern in EnhancedValidator.PUBLIC_KEY_PATTERNS.values()):
            raise ValidationError(
                message="Invalid public key format. Must be in PEM format",
                field=field_name,
                value=public_key[:100] + "..." if len(public_key) > 100 else public_key
            )
        
        return public_key
    
    @staticmethod
    def validate_signature(signature: str, field_name: str = 'signature') -> str:
        """
        Validate signature format.
        
        Args:
            signature: Signature to validate
            field_name: Field name for error reporting
            
        Returns:
            Validated signature
            
        Raises:
            ValidationError: If signature is invalid
        """
        if not signature:
            raise ValidationError(
                message="Signature is required",
                field=field_name,
                value=signature
            )
        
        if not isinstance(signature, str):
            raise ValidationError(
                message="Signature must be a string",
                field=field_name,
                value=str(signature)
            )
        
        signature = signature.strip()
        
        # Check if it's a valid hex or base64 format
        if not any(pattern.match(signature) for pattern in EnhancedValidator.SIGNATURE_PATTERNS.values()):
            raise ValidationError(
                message="Invalid signature format. Must be hex or base64 encoded",
                field=field_name,
                value=signature[:50] + "..." if len(signature) > 50 else signature
            )
        
        return signature
    
    @staticmethod
    def validate_device_name(device_name: str, field_name: str = 'device_name') -> str:
        """
        Validate device name format.
        
        Args:
            device_name: Device name to validate
            field_name: Field name for error reporting
            
        Returns:
            Validated device name
            
        Raises:
            ValidationError: If device name is invalid
        """
        if not device_name:
            return "Unknown Device"
        
        if not isinstance(device_name, str):
            raise ValidationError(
                message="Device name must be a string",
                field=field_name,
                value=str(device_name)
            )
        
        device_name = device_name.strip()
        
        if len(device_name) > 50:
            raise ValidationError(
                message="Device name must be 50 characters or less",
                field=field_name,
                value=device_name
            )
        
        if not EnhancedValidator.DEVICE_NAME_REGEX.match(device_name):
            raise ValidationError(
                message="Device name contains invalid characters. Use only letters, numbers, spaces, hyphens, underscores, and periods",
                field=field_name,
                value=device_name
            )
        
        return device_name
    
    @staticmethod
    def validate_verification_code(code: str, field_name: str = 'verification_code') -> str:
        """
        Validate verification code format.
        
        Args:
            code: Verification code to validate
            field_name: Field name for error reporting
            
        Returns:
            Validated verification code
            
        Raises:
            ValidationError: If verification code is invalid
        """
        if not code:
            raise ValidationError(
                message="Verification code is required",
                field=field_name,
                value=code
            )
        
        if not isinstance(code, str):
            raise ValidationError(
                message="Verification code must be a string",
                field=field_name,
                value=str(code)
            )
        
        code = code.strip()
        
        if not EnhancedValidator.VERIFICATION_CODE_REGEX.match(code):
            raise ValidationError(
                message="Verification code must be exactly 6 digits",
                field=field_name,
                value=code
            )
        
        return code
    
    @staticmethod
    def validate_nonce(nonce: str, field_name: str = 'nonce') -> str:
        """
        Validate nonce format.
        
        Args:
            nonce: Nonce to validate
            field_name: Field name for error reporting
            
        Returns:
            Validated nonce
            
        Raises:
            ValidationError: If nonce is invalid
        """
        if not nonce:
            raise ValidationError(
                message="Nonce is required",
                field=field_name,
                value=nonce
            )
        
        if not isinstance(nonce, str):
            raise ValidationError(
                message="Nonce must be a string",
                field=field_name,
                value=str(nonce)
            )
        
        nonce = nonce.strip()
        
        # Nonce should be alphanumeric and reasonable length
        if not re.match(r'^[a-zA-Z0-9]{16,64}$', nonce):
            raise ValidationError(
                message="Invalid nonce format",
                field=field_name,
                value=nonce[:20] + "..." if len(nonce) > 20 else nonce
            )
        
        return nonce
    
    @staticmethod
    def validate_request_data(data: Dict[str, Any], required_fields: List[str], 
                            optional_fields: List[str] = None) -> Dict[str, Any]:
        """
        Validate request data against required and optional fields.
        
        Args:
            data: Request data to validate
            required_fields: List of required field names
            optional_fields: List of optional field names
            
        Returns:
            Validated data dictionary
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(data, dict):
            raise ValidationError(
                message="Request data must be a JSON object",
                field="request_body"
            )
        
        validated_data = {}
        missing_fields = []
        
        # Check required fields
        for field in required_fields:
            if field not in data or data[field] is None or data[field] == "":
                missing_fields.append(field)
            else:
                validated_data[field] = data[field]
        
        if missing_fields:
            raise ValidationError(
                message=f"Missing required fields: {', '.join(missing_fields)}",
                field="required_fields",
                value=str(missing_fields)
            )
        
        # Add optional fields if present
        if optional_fields:
            for field in optional_fields:
                if field in data and data[field] is not None:
                    validated_data[field] = data[field]
        
        return validated_data
    
    @staticmethod
    def validate_json_request() -> Dict[str, Any]:
        """
        Validate that request contains valid JSON.
        
        Returns:
            Parsed JSON data
            
        Raises:
            ValidationError: If JSON is invalid
        """
        if not request.is_json:
            raise ValidationError(
                message="Request must contain valid JSON",
                field="content_type"
            )
        
        try:
            data = request.get_json()
            if data is None:
                raise ValidationError(
                    message="Request body is empty or invalid JSON",
                    field="request_body"
                )
            return data
        except Exception as e:
            raise ValidationError(
                message="Invalid JSON format",
                field="request_body",
                value=str(e)
            )

def validate_request_schema(required_fields: List[str], optional_fields: List[str] = None):
    """
    Decorator to validate request schema.
    
    Args:
        required_fields: List of required field names
        optional_fields: List of optional field names
    """
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Validate JSON request
                data = EnhancedValidator.validate_json_request()
                
                # Validate required and optional fields
                validated_data = EnhancedValidator.validate_request_data(
                    data, required_fields, optional_fields or []
                )
                
                # Store validated data in request object
                request.validated_data = validated_data
                
                return f(*args, **kwargs)
                
            except ValidationError as e:
                # Let the error handler deal with it
                raise e
            except Exception as e:
                logger.error(f"Unexpected error in request validation: {str(e)}")
                raise ValidationError(
                    message="Request validation failed",
                    field="validation",
                    value=str(e)
                )
        
        return decorated_function
    return decorator

def sanitize_inputs():
    """
    Decorator to sanitize input data.
    """
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                if hasattr(request, 'validated_data'):
                    # Sanitize string inputs
                    for key, value in request.validated_data.items():
                        if isinstance(value, str):
                            # Remove leading/trailing whitespace
                            request.validated_data[key] = value.strip()
                            
                            # Basic XSS prevention (remove script tags)
                            if '<script' in value.lower():
                                raise ValidationError(
                                    message="Invalid input detected",
                                    field=key,
                                    value="[REDACTED]"
                                )
                
                return f(*args, **kwargs)
                
            except ValidationError as e:
                raise e
            except Exception as e:
                logger.error(f"Unexpected error in input sanitization: {str(e)}")
                raise ValidationError(
                    message="Input sanitization failed",
                    field="sanitization",
                    value=str(e)
                )
        
        return decorated_function
    return decorator 