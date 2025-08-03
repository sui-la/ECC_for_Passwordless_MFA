"""
Comprehensive error handling system for ECC Passwordless MFA.
Provides structured error responses, proper error codes, and logging.
"""

import logging
import traceback
from typing import Dict, Any, Optional, Union
from flask import jsonify, request
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

class ECCError(Exception):
    """Base exception class for ECC MFA system."""
    
    def __init__(self, message: str, error_code: str, status_code: int = 400, 
                 details: Optional[Dict[str, Any]] = None, user_friendly: bool = True):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        self.user_friendly = user_friendly
        self.timestamp = datetime.utcnow().isoformat()
        self.request_id = str(uuid.uuid4())

class ValidationError(ECCError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Optional[str] = None):
        details = {}
        if field:
            details['field'] = field
        if value:
            details['value'] = value
        
        super().__init__(
            message=message,
            error_code='VALIDATION_ERROR',
            status_code=400,
            details=details
        )

class AuthenticationError(ECCError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str, auth_type: str = 'general'):
        super().__init__(
            message=message,
            error_code='AUTHENTICATION_ERROR',
            status_code=401,
            details={'auth_type': auth_type}
        )

class AuthorizationError(ECCError):
    """Raised when authorization fails."""
    
    def __init__(self, message: str, resource: Optional[str] = None):
        details = {}
        if resource:
            details['resource'] = resource
        
        super().__init__(
            message=message,
            error_code='AUTHORIZATION_ERROR',
            status_code=403,
            details=details
        )

class NotFoundError(ECCError):
    """Raised when a resource is not found."""
    
    def __init__(self, message: str, resource_type: Optional[str] = None, resource_id: Optional[str] = None):
        details = {}
        if resource_type:
            details['resource_type'] = resource_type
        if resource_id:
            details['resource_id'] = resource_id
        
        super().__init__(
            message=message,
            error_code='NOT_FOUND',
            status_code=404,
            details=details
        )

class RateLimitError(ECCError):
    """Raised when rate limiting is exceeded."""
    
    def __init__(self, message: str, retry_after: Optional[int] = None):
        details = {}
        if retry_after:
            details['retry_after'] = retry_after
        
        super().__init__(
            message=message,
            error_code='RATE_LIMIT_EXCEEDED',
            status_code=429,
            details=details
        )

class DatabaseError(ECCError):
    """Raised when database operations fail."""
    
    def __init__(self, message: str, operation: Optional[str] = None):
        details = {}
        if operation:
            details['operation'] = operation
        
        super().__init__(
            message=message,
            error_code='DATABASE_ERROR',
            status_code=500,
            details=details,
            user_friendly=False
        )

class CryptoError(ECCError):
    """Raised when cryptographic operations fail."""
    
    def __init__(self, message: str, operation: Optional[str] = None):
        details = {}
        if operation:
            details['operation'] = operation
        
        super().__init__(
            message=message,
            error_code='CRYPTO_ERROR',
            status_code=500,
            details=details,
            user_friendly=False
        )

class EmailError(ECCError):
    """Raised when email operations fail."""
    
    def __init__(self, message: str, email: Optional[str] = None):
        details = {}
        if email:
            details['email'] = email
        
        super().__init__(
            message=message,
            error_code='EMAIL_ERROR',
            status_code=500,
            details=details
        )

class SessionError(ECCError):
    """Raised when session operations fail."""
    
    def __init__(self, message: str, session_id: Optional[str] = None):
        details = {}
        if session_id:
            details['session_id'] = session_id
        
        super().__init__(
            message=message,
            error_code='SESSION_ERROR',
            status_code=401,
            details=details
        )

# Error code mappings for common scenarios
ERROR_CODES = {
    # Authentication & Authorization
    'INVALID_TOKEN': {'code': 'AUTHENTICATION_ERROR', 'status': 401, 'message': 'Invalid or expired authentication token'},
    'MISSING_TOKEN': {'code': 'AUTHENTICATION_ERROR', 'status': 401, 'message': 'Authentication token is required'},
    'INSUFFICIENT_PERMISSIONS': {'code': 'AUTHORIZATION_ERROR', 'status': 403, 'message': 'Insufficient permissions to access this resource'},
    
    # Validation
    'MISSING_REQUIRED_FIELD': {'code': 'VALIDATION_ERROR', 'status': 400, 'message': 'Required field is missing'},
    'INVALID_EMAIL_FORMAT': {'code': 'VALIDATION_ERROR', 'status': 400, 'message': 'Invalid email format'},
    'INVALID_PUBLIC_KEY': {'code': 'VALIDATION_ERROR', 'status': 400, 'message': 'Invalid public key format'},
    'INVALID_SIGNATURE': {'code': 'VALIDATION_ERROR', 'status': 400, 'message': 'Invalid signature format'},
    
    # Resources
    'USER_NOT_FOUND': {'code': 'NOT_FOUND', 'status': 404, 'message': 'User not found'},
    'DEVICE_NOT_FOUND': {'code': 'NOT_FOUND', 'status': 404, 'message': 'Device not found'},
    'SESSION_NOT_FOUND': {'code': 'NOT_FOUND', 'status': 404, 'message': 'Session not found'},
    'MESSAGE_NOT_FOUND': {'code': 'NOT_FOUND', 'status': 404, 'message': 'Message not found'},
    
    # Business Logic
    'USER_ALREADY_EXISTS': {'code': 'VALIDATION_ERROR', 'status': 409, 'message': 'User already exists'},
    'DEVICE_ALREADY_REGISTERED': {'code': 'VALIDATION_ERROR', 'status': 409, 'message': 'Device already registered'},
    'EMAIL_NOT_VERIFIED': {'code': 'AUTHORIZATION_ERROR', 'status': 403, 'message': 'Email address not verified'},
    'INVALID_VERIFICATION_CODE': {'code': 'VALIDATION_ERROR', 'status': 400, 'message': 'Invalid verification code'},
    'VERIFICATION_CODE_EXPIRED': {'code': 'VALIDATION_ERROR', 'status': 400, 'message': 'Verification code has expired'},
    
    # Rate Limiting
    'RATE_LIMIT_EXCEEDED': {'code': 'RATE_LIMIT_EXCEEDED', 'status': 429, 'message': 'Too many requests. Please try again later'},
    
    # System Errors
    'INTERNAL_SERVER_ERROR': {'code': 'SYSTEM_ERROR', 'status': 500, 'message': 'Internal server error occurred'},
    'DATABASE_CONNECTION_ERROR': {'code': 'DATABASE_ERROR', 'status': 500, 'message': 'Database connection error'},
    'REDIS_CONNECTION_ERROR': {'code': 'SYSTEM_ERROR', 'status': 500, 'message': 'Cache connection error'},
    'EMAIL_SEND_ERROR': {'code': 'EMAIL_ERROR', 'status': 500, 'message': 'Failed to send email'},
}

def create_error_response(error: ECCError, include_details: bool = False) -> Dict[str, Any]:
    """
    Create a structured error response.
    
    Args:
        error: ECCError instance
        include_details: Whether to include detailed error information
        
    Returns:
        Dict containing structured error response
    """
    response = {
        'error': True,
        'message': error.message,
        'code': error.error_code,
        'timestamp': error.timestamp,
        'request_id': error.request_id
    }
    
    if include_details and error.details:
        response['details'] = error.details
    
    return response

def handle_validation_error(error: ValidationError) -> tuple:
    """Handle validation errors with structured response."""
    response = create_error_response(error, include_details=True)
    logger.warning(f"Validation error: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_authentication_error(error: AuthenticationError) -> tuple:
    """Handle authentication errors with structured response."""
    response = create_error_response(error)
    logger.warning(f"Authentication error: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_authorization_error(error: AuthorizationError) -> tuple:
    """Handle authorization errors with structured response."""
    response = create_error_response(error)
    logger.warning(f"Authorization error: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_not_found_error(error: NotFoundError) -> tuple:
    """Handle not found errors with structured response."""
    response = create_error_response(error, include_details=True)
    logger.info(f"Resource not found: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_rate_limit_error(error: RateLimitError) -> tuple:
    """Handle rate limit errors with structured response."""
    response = create_error_response(error, include_details=True)
    logger.warning(f"Rate limit exceeded: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_system_error(error: ECCError) -> tuple:
    """Handle system errors with structured response."""
    # Don't expose internal details to users
    user_message = "An internal error occurred. Please try again later."
    if error.user_friendly:
        user_message = error.message
    
    response = {
        'error': True,
        'message': user_message,
        'code': error.error_code,
        'timestamp': error.timestamp,
        'request_id': error.request_id
    }
    
    # Log full error details for debugging
    logger.error(f"System error: {error.message} - {error.details} - Traceback: {traceback.format_exc()}")
    
    return jsonify(response), error.status_code

def handle_generic_exception(exception: Exception) -> tuple:
    """Handle generic exceptions with structured response."""
    error_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    
    # Log the full exception for debugging
    logger.error(f"Unhandled exception (ID: {error_id}): {str(exception)} - Traceback: {traceback.format_exc()}")
    
    response = {
        'error': True,
        'message': 'An unexpected error occurred. Please try again later.',
        'code': 'INTERNAL_SERVER_ERROR',
        'timestamp': timestamp,
        'request_id': error_id
    }
    
    return jsonify(response), 500

def log_request_error(request_info: Dict[str, Any], error: ECCError):
    """Log request error with context."""
    log_data = {
        'request_id': error.request_id,
        'method': request_info.get('method'),
        'url': request_info.get('url'),
        'ip_address': request_info.get('ip_address'),
        'user_agent': request_info.get('user_agent'),
        'error_code': error.error_code,
        'error_message': error.message,
        'status_code': error.status_code,
        'timestamp': error.timestamp
    }
    
    if error.status_code >= 500:
        logger.error(f"Request error: {log_data}")
    elif error.status_code >= 400:
        logger.warning(f"Request error: {log_data}")
    else:
        logger.info(f"Request error: {log_data}")

def get_request_info() -> Dict[str, Any]:
    """Get current request information."""
    return {
        'method': request.method,
        'url': request.url,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'headers': dict(request.headers)
    }

# Decorator for error handling
def handle_errors(f):
    """Decorator to handle errors in route functions."""
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ECCError as e:
            request_info = get_request_info()
            log_request_error(request_info, e)
            
            if isinstance(e, ValidationError):
                return handle_validation_error(e)
            elif isinstance(e, AuthenticationError):
                return handle_authentication_error(e)
            elif isinstance(e, AuthorizationError):
                return handle_authorization_error(e)
            elif isinstance(e, NotFoundError):
                return handle_not_found_error(e)
            elif isinstance(e, RateLimitError):
                return handle_rate_limit_error(e)
            else:
                return handle_system_error(e)
        except Exception as e:
            request_info = get_request_info()
            logger.error(f"Unhandled exception in {f.__name__}: {str(e)}")
            return handle_generic_exception(e)
    
    return decorated_function

# Error response helpers
def error_response(message: str, error_code: str, status_code: int = 400, 
                  details: Optional[Dict[str, Any]] = None) -> tuple:
    """Create a quick error response."""
    error = ECCError(message, error_code, status_code, details)
    return handle_system_error(error)

def validation_error(message: str, field: Optional[str] = None, value: Optional[str] = None) -> tuple:
    """Create a validation error response."""
    error = ValidationError(message, field, value)
    return handle_validation_error(error)

def not_found_error(message: str, resource_type: Optional[str] = None, 
                   resource_id: Optional[str] = None) -> tuple:
    """Create a not found error response."""
    error = NotFoundError(message, resource_type, resource_id)
    return handle_not_found_error(error)

def authentication_error(message: str, auth_type: str = 'general') -> tuple:
    """Create an authentication error response."""
    error = AuthenticationError(message, auth_type)
    return handle_authentication_error(error)

def authorization_error(message: str, resource: Optional[str] = None) -> tuple:
    """Create an authorization error response."""
    error = AuthorizationError(message, resource)
    return handle_authorization_error(error) 