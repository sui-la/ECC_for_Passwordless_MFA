"""
Enhanced Error Handler for ECC Passwordless MFA.
Provides better error categorization, user-friendly messages, and detailed logging.
"""

import logging
import traceback
from datetime import datetime
from typing import Dict, Any, Optional
from flask import jsonify, request
from utils.error_handler import ECCError, ValidationError, AuthenticationError, AuthorizationError, NotFoundError, RateLimitError

# Configure logger
logger = logging.getLogger(__name__)

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

class EnhancedErrorHandler:
    """Enhanced error handler with better categorization and user-friendly messages."""
    
    # User-friendly error messages
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
    
    # Error categorization mapping
    ERROR_CATEGORIES = {
        # Authentication errors
        "invalid_credentials": ErrorCategory.AUTHENTICATION,
        "token_expired": ErrorCategory.AUTHENTICATION,
        "token_invalid": ErrorCategory.AUTHENTICATION,
        "email_not_verified": ErrorCategory.AUTHENTICATION,
        "device_not_found": ErrorCategory.AUTHENTICATION,
        "signature_verification_failed": ErrorCategory.AUTHENTICATION,
        
        # Validation errors
        "invalid_email": ErrorCategory.VALIDATION,
        "invalid_public_key": ErrorCategory.VALIDATION,
        "invalid_signature": ErrorCategory.VALIDATION,
        "missing_required_field": ErrorCategory.VALIDATION,
        "email_already_exists": ErrorCategory.VALIDATION,
        
        # Rate limiting
        "rate_limit_exceeded": ErrorCategory.RATE_LIMIT,
        "auth_rate_limit": ErrorCategory.RATE_LIMIT,
        "registration_rate_limit": ErrorCategory.RATE_LIMIT,
        
        # System errors
        "database_error": ErrorCategory.DATABASE,
        "crypto_error": ErrorCategory.CRYPTO,
        "email_error": ErrorCategory.EMAIL,
        "session_error": ErrorCategory.SESSION,
        
        # Generic errors
        "internal_error": ErrorCategory.SYSTEM,
        "service_unavailable": ErrorCategory.SYSTEM,
        "not_found": ErrorCategory.SYSTEM,
        "forbidden": ErrorCategory.AUTHORIZATION,
    }
    
    # Error severity mapping
    ERROR_SEVERITY = {
        # Low severity - user errors
        "invalid_email": ErrorSeverity.LOW,
        "missing_required_field": ErrorSeverity.LOW,
        "not_found": ErrorSeverity.LOW,
        
        # Medium severity - authentication/validation
        "invalid_credentials": ErrorSeverity.MEDIUM,
        "token_expired": ErrorSeverity.MEDIUM,
        "token_invalid": ErrorSeverity.MEDIUM,
        "invalid_public_key": ErrorSeverity.MEDIUM,
        "invalid_signature": ErrorSeverity.MEDIUM,
        "email_not_verified": ErrorSeverity.MEDIUM,
        "rate_limit_exceeded": ErrorSeverity.MEDIUM,
        
        # High severity - system issues
        "database_error": ErrorSeverity.HIGH,
        "email_error": ErrorSeverity.HIGH,
        "session_error": ErrorSeverity.HIGH,
        "crypto_error": ErrorSeverity.HIGH,
        
        # Critical severity - security issues
        "signature_verification_failed": ErrorSeverity.CRITICAL,
        "forbidden": ErrorSeverity.CRITICAL,
        "internal_error": ErrorSeverity.CRITICAL,
    }
    
    @classmethod
    def create_error_response(cls, error: Exception, error_code: str = None, 
                            user_message: str = None, category: str = None,
                            severity: str = None, details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a comprehensive error response."""
        
        # Generate error code if not provided
        if not error_code:
            error_code = cls._generate_error_code(error)
        
        # Get user-friendly message
        if not user_message:
            user_message = cls.USER_FRIENDLY_MESSAGES.get(error_code, "An error occurred. Please try again.")
        
        # Determine category
        if not category:
            category = cls.ERROR_CATEGORIES.get(error_code, ErrorCategory.SYSTEM)
        
        # Determine severity
        if not severity:
            severity = cls.ERROR_SEVERITY.get(error_code, ErrorSeverity.MEDIUM)
        
        # Create error response
        error_response = {
            "error": {
                "code": error_code,
                "message": user_message,
                "category": category,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "request_id": cls._get_request_id(),
                "path": request.path if request else None,
                "method": request.method if request else None,
            }
        }
        
        # Add details if provided
        if details:
            error_response["error"]["details"] = details
        
        # Add technical details in development
        if cls._is_development():
            error_response["error"]["technical_details"] = {
                "exception_type": type(error).__name__,
                "exception_message": str(error),
                "traceback": traceback.format_exc() if cls._is_development() else None
            }
        
        return error_response
    
    @classmethod
    def log_error(cls, error: Exception, error_code: str = None, 
                  category: str = None, severity: str = None,
                  context: Dict[str, Any] = None):
        """Log error with enhanced context."""
        
        # Generate error code if not provided
        if not error_code:
            error_code = cls._generate_error_code(error)
        
        # Determine category and severity
        if not category:
            category = cls.ERROR_CATEGORIES.get(error_code, ErrorCategory.SYSTEM)
        if not severity:
            severity = cls.ERROR_SEVERITY.get(error_code, ErrorSeverity.MEDIUM)
        
        # Prepare log message
        log_data = {
            "error_code": error_code,
            "category": category,
            "severity": severity,
            "exception_type": type(error).__name__,
            "exception_message": str(error),
            "request_id": cls._get_request_id(),
            "path": request.path if request else None,
            "method": request.method if request else None,
            "user_agent": request.headers.get('User-Agent') if request else None,
            "ip_address": request.remote_addr if request else None,
            "timestamp": datetime.now().isoformat(),
        }
        
        # Add context if provided
        if context:
            log_data["context"] = context
        
        # Add traceback for debugging
        if cls._is_development() or severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            log_data["traceback"] = traceback.format_exc()
        
        # Log based on severity
        if severity == ErrorSeverity.CRITICAL:
            logger.critical("Critical error occurred", extra=log_data)
        elif severity == ErrorSeverity.HIGH:
            logger.error("High severity error occurred", extra=log_data)
        elif severity == ErrorSeverity.MEDIUM:
            logger.warning("Medium severity error occurred", extra=log_data)
        else:
            logger.info("Low severity error occurred", extra=log_data)
    
    @classmethod
    def handle_validation_error(cls, error: ValidationError):
        """Handle validation errors with enhanced response."""
        error_code = "validation_error"
        user_message = cls.USER_FRIENDLY_MESSAGES.get(error.message, "Please check your input and try again.")
        
        response = cls.create_error_response(
            error=error,
            error_code=error_code,
            user_message=user_message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.LOW,
            details={"field": getattr(error, 'field', None)}
        )
        
        cls.log_error(error, error_code, ErrorCategory.VALIDATION, ErrorSeverity.LOW)
        return jsonify(response), 400
    
    @classmethod
    def handle_authentication_error(cls, error: AuthenticationError):
        """Handle authentication errors with enhanced response."""
        error_code = "authentication_error"
        user_message = cls.USER_FRIENDLY_MESSAGES.get(error.message, "Authentication failed. Please try again.")
        
        response = cls.create_error_response(
            error=error,
            error_code=error_code,
            user_message=user_message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.MEDIUM
        )
        
        cls.log_error(error, error_code, ErrorCategory.AUTHENTICATION, ErrorSeverity.MEDIUM)
        return jsonify(response), 401
    
    @classmethod
    def handle_authorization_error(cls, error: AuthorizationError):
        """Handle authorization errors with enhanced response."""
        error_code = "authorization_error"
        user_message = cls.USER_FRIENDLY_MESSAGES.get(error.message, "You don't have permission to perform this action.")
        
        response = cls.create_error_response(
            error=error,
            error_code=error_code,
            user_message=user_message,
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.CRITICAL
        )
        
        cls.log_error(error, error_code, ErrorCategory.AUTHORIZATION, ErrorSeverity.CRITICAL)
        return jsonify(response), 403
    
    @classmethod
    def handle_not_found_error(cls, error: NotFoundError):
        """Handle not found errors with enhanced response."""
        error_code = "not_found"
        user_message = cls.USER_FRIENDLY_MESSAGES.get(error.message, "The requested resource was not found.")
        
        response = cls.create_error_response(
            error=error,
            error_code=error_code,
            user_message=user_message,
            category=ErrorCategory.SYSTEM,
            severity=ErrorSeverity.LOW
        )
        
        cls.log_error(error, error_code, ErrorCategory.SYSTEM, ErrorSeverity.LOW)
        return jsonify(response), 404
    
    @classmethod
    def handle_rate_limit_error(cls, error: RateLimitError):
        """Handle rate limit errors with enhanced response."""
        error_code = "rate_limit_exceeded"
        user_message = cls.USER_FRIENDLY_MESSAGES.get(error.message, "Too many requests. Please wait before trying again.")
        
        response = cls.create_error_response(
            error=error,
            error_code=error_code,
            user_message=user_message,
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.MEDIUM,
            details={"retry_after": getattr(error, 'retry_after', 60)}
        )
        
        cls.log_error(error, error_code, ErrorCategory.RATE_LIMIT, ErrorSeverity.MEDIUM)
        return jsonify(response), 429
    
    @classmethod
    def handle_generic_exception(cls, error: Exception):
        """Handle generic exceptions with enhanced response."""
        error_code = "internal_error"
        user_message = cls.USER_FRIENDLY_MESSAGES.get(error_code, "An unexpected error occurred. Please try again later.")
        
        response = cls.create_error_response(
            error=error,
            error_code=error_code,
            user_message=user_message,
            category=ErrorCategory.SYSTEM,
            severity=ErrorSeverity.HIGH
        )
        
        cls.log_error(error, error_code, ErrorCategory.SYSTEM, ErrorSeverity.HIGH)
        return jsonify(response), 500
    
    @classmethod
    def _generate_error_code(cls, error: Exception) -> str:
        """Generate error code from exception."""
        if hasattr(error, 'error_code'):
            return error.error_code
        
        # Generate code from exception type
        error_type = type(error).__name__.lower()
        if 'validation' in error_type:
            return 'validation_error'
        elif 'auth' in error_type:
            return 'authentication_error'
        elif 'rate' in error_type:
            return 'rate_limit_error'
        elif 'notfound' in error_type:
            return 'not_found'
        else:
            return 'internal_error'
    
    @classmethod
    def _get_request_id(cls) -> str:
        """Get request ID from Flask request context."""
        if hasattr(request, 'request_id'):
            return request.request_id
        return "unknown"
    
    @classmethod
    def _is_development(cls) -> bool:
        """Check if running in development mode."""
        import os
        return os.environ.get('FLASK_ENV', 'development') == 'development'

# Convenience functions
def handle_validation_error(error: ValidationError):
    """Handle validation errors."""
    return EnhancedErrorHandler.handle_validation_error(error)

def handle_authentication_error(error: AuthenticationError):
    """Handle authentication errors."""
    return EnhancedErrorHandler.handle_authentication_error(error)

def handle_authorization_error(error: AuthorizationError):
    """Handle authorization errors."""
    return EnhancedErrorHandler.handle_authorization_error(error)

def handle_not_found_error(error: NotFoundError):
    """Handle not found errors."""
    return EnhancedErrorHandler.handle_not_found_error(error)

def handle_rate_limit_error(error: RateLimitError):
    """Handle rate limit errors."""
    return EnhancedErrorHandler.handle_rate_limit_error(error)

def handle_generic_exception(error: Exception):
    """Handle generic exceptions."""
    return EnhancedErrorHandler.handle_generic_exception(error) 