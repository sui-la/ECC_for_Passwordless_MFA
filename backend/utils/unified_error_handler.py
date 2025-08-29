"""
Unified Error Handler for ECC Passwordless MFA.
Combines exception classes and enhanced error handling in one clean module.
"""

import logging
import traceback
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, Union
from flask import jsonify, request

logger = logging.getLogger(__name__)

# ============================================================================
# EXCEPTION CLASSES
# ============================================================================

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

# ============================================================================
# ERROR CATEGORIES AND SEVERITY
# ============================================================================

class ErrorCategory:
    """Error categories for better organization."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    DATABASE = "database"
    CRYPTO = "cryptographic"
    NETWORK = "network"
    SYSTEM = "system"
    RATE_LIMIT = "rate_limit"
    EMAIL = "email"
    SESSION = "session"

class ErrorSeverity:
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# ============================================================================
# USER-FRIENDLY MESSAGES
# ============================================================================

USER_FRIENDLY_MESSAGES = {
    # Authentication errors
    "invalid_credentials": "The provided credentials are incorrect. Please try again.",
    "token_expired": "Your session has expired. Please sign in again.",
    "token_invalid": "Invalid authentication token. Please sign in again.",
    "email_not_verified": "Please verify your email address before signing in.",
    "device_not_found": "The specified device was not found.",
    "signature_verification_failed": "Authentication failed. Please try again.",
    
    # Validation errors
    "invalid_email": "Please enter a valid email address.",
    "invalid_public_key": "The provided public key is invalid.",
    "invalid_signature": "The provided signature is invalid.",
    "missing_required_field": "Please fill in all required fields.",
    "email_already_exists": "An account with this email already exists.",
    
    # Rate limiting
    "rate_limit_exceeded": "Too many attempts. Please wait a moment before trying again.",
    "auth_rate_limit": "Too many authentication attempts. Please wait before trying again.",
    "registration_rate_limit": "Too many registration attempts. Please wait before trying again.",
    
    # System errors
    "database_error": "A system error occurred. Please try again later.",
    "crypto_error": "A security error occurred. Please try again.",
    "email_error": "Unable to send email. Please try again later.",
    "session_error": "Session error. Please sign in again.",
    
    # Generic errors
    "internal_error": "An unexpected error occurred. Please try again later.",
    "service_unavailable": "Service temporarily unavailable. Please try again later.",
    "not_found": "The requested resource was not found.",
    "forbidden": "You don't have permission to access this resource.",
}

# ============================================================================
# ERROR HANDLING FUNCTIONS
# ============================================================================

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
    """Handle validation errors with enhanced response."""
    user_message = USER_FRIENDLY_MESSAGES.get(error.message, "Please check your input and try again.")
    
    response = {
        'error': True,
        'message': user_message,
        'code': error.error_code,
        'timestamp': error.timestamp,
        'request_id': error.request_id,
        'category': ErrorCategory.VALIDATION,
        'severity': ErrorSeverity.LOW
    }
    
    if error.details:
        response['details'] = error.details
    
    logger.warning(f"Validation error: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_authentication_error(error: AuthenticationError) -> tuple:
    """Handle authentication errors with enhanced response."""
    user_message = USER_FRIENDLY_MESSAGES.get(error.message, "Authentication failed. Please try again.")
    
    response = {
        'error': True,
        'message': user_message,
        'code': error.error_code,
        'timestamp': error.timestamp,
        'request_id': error.request_id,
        'category': ErrorCategory.AUTHENTICATION,
        'severity': ErrorSeverity.MEDIUM
    }
    
    logger.warning(f"Authentication error: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_authorization_error(error: AuthorizationError) -> tuple:
    """Handle authorization errors with enhanced response."""
    user_message = USER_FRIENDLY_MESSAGES.get(error.message, "You don't have permission to perform this action.")
    
    response = {
        'error': True,
        'message': user_message,
        'code': error.error_code,
        'timestamp': error.timestamp,
        'request_id': error.request_id,
        'category': ErrorCategory.AUTHORIZATION,
        'severity': ErrorSeverity.CRITICAL
    }
    
    logger.warning(f"Authorization error: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_not_found_error(error: NotFoundError) -> tuple:
    """Handle not found errors with enhanced response."""
    user_message = USER_FRIENDLY_MESSAGES.get(error.message, "The requested resource was not found.")
    
    response = {
        'error': True,
        'message': user_message,
        'code': error.error_code,
        'timestamp': error.timestamp,
        'request_id': error.request_id,
        'category': ErrorCategory.SYSTEM,
        'severity': ErrorSeverity.LOW
    }
    
    if error.details:
        response['details'] = error.details
    
    logger.info(f"Resource not found: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_rate_limit_error(error: RateLimitError) -> tuple:
    """Handle rate limit errors with enhanced response."""
    user_message = USER_FRIENDLY_MESSAGES.get(error.message, "Too many requests. Please wait before trying again.")
    
    response = {
        'error': True,
        'message': user_message,
        'code': error.error_code,
        'timestamp': error.timestamp,
        'request_id': error.request_id,
        'category': ErrorCategory.RATE_LIMIT,
        'severity': ErrorSeverity.MEDIUM
    }
    
    if error.details:
        response['details'] = error.details
    
    logger.warning(f"Rate limit exceeded: {error.message} - {error.details}")
    return jsonify(response), error.status_code

def handle_generic_exception(error: Exception) -> tuple:
    """Handle generic exceptions with enhanced response."""
    error_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    
    # Don't expose internal details to users
    user_message = "An unexpected error occurred. Please try again later."
    
    response = {
        'error': True,
        'message': user_message,
        'code': 'INTERNAL_SERVER_ERROR',
        'timestamp': timestamp,
        'request_id': error_id,
        'category': ErrorCategory.SYSTEM,
        'severity': ErrorSeverity.HIGH
    }
    
    # Log the full exception for debugging
    logger.error(f"Unhandled exception (ID: {error_id}): {str(error)} - Traceback: {traceback.format_exc()}")
    
    return jsonify(response), 500

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

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

# ============================================================================
# DECORATOR FOR ERROR HANDLING
# ============================================================================

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
                return handle_generic_exception(e)
        except Exception as e:
            request_info = get_request_info()
            logger.error(f"Unhandled exception in {f.__name__}: {str(e)}")
            return handle_generic_exception(e)
    
    return decorated_function

# ============================================================================
# QUICK ERROR RESPONSE HELPERS
# ============================================================================

def error_response(message: str, error_code: str, status_code: int = 400, 
                  details: Optional[Dict[str, Any]] = None) -> tuple:
    """Create a quick error response."""
    error = ECCError(message, error_code, status_code, details)
    return handle_generic_exception(error)

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
