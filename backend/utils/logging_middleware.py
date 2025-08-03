"""
Logging middleware for Flask application.
Automatically logs requests, responses, and performance metrics.
"""

import time
import logging
from typing import Optional, Dict, Any
from flask import request, g, Response
from functools import wraps
from .logging_config import log_access_event, log_request_context, log_security_event, log_audit_event

logger = logging.getLogger(__name__)

class RequestLoggingMiddleware:
    """Middleware for comprehensive request logging."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the middleware with the Flask app."""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.teardown_request(self.teardown_request)
    
    def before_request(self):
        """Log request details before processing."""
        # Generate request ID
        g.request_id = self._generate_request_id()
        g.start_time = time.time()
        
        # Extract request information
        request_info = {
            'method': request.method,
            'path': request.path,
            'ip_address': self._get_client_ip(),
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'content_type': request.headers.get('Content-Type', 'Unknown'),
            'content_length': request.content_length or 0
        }
        
        # Add request context to logging
        log_request_context(
            request_id=g.request_id,
            ip_address=request_info['ip_address']
        )
        
        # Log request start
        logger.info(f"Request started: {request.method} {request.path}", extra={
            'request_id': g.request_id,
            'ip_address': request_info['ip_address'],
            'user_agent': request_info['user_agent']
        })
        
        # Store request info for later use
        g.request_info = request_info
    
    def after_request(self, response: Response) -> Response:
        """Log response details after processing."""
        if hasattr(g, 'start_time'):
            response_time = time.time() - g.start_time
            
            # Log access event
            log_access_event(
                method=g.request_info['method'],
                path=g.request_info['path'],
                status_code=response.status_code,
                response_time=response_time,
                request_id=g.request_id,
                ip_address=g.request_info['ip_address'],
                user_agent=g.request_info['user_agent'],
                content_length=g.request_info['content_length'],
                response_size=len(response.get_data()) if response.get_data() else 0
            )
            
            # Log response details
            logger.info(f"Request completed: {g.request_info['method']} {g.request_info['path']} {response.status_code} ({response_time:.3f}s)", extra={
                'request_id': g.request_id,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_size': len(response.get_data()) if response.get_data() else 0
            })
            
            # Add request ID to response headers
            response.headers['X-Request-ID'] = g.request_id
        
        return response
    
    def teardown_request(self, exception=None):
        """Handle request teardown and exception logging."""
        if exception:
            logger.error(f"Request failed with exception: {str(exception)}", extra={
                'request_id': getattr(g, 'request_id', 'unknown'),
                'exception_type': type(exception).__name__,
                'exception_message': str(exception)
            })
        
        # Clean up request context
        if hasattr(g, 'request_id'):
            del g.request_id
        if hasattr(g, 'start_time'):
            del g.start_time
        if hasattr(g, 'request_info'):
            del g.request_info
    
    def _generate_request_id(self) -> str:
        """Generate a unique request ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _get_client_ip(self) -> str:
        """Get the client's real IP address."""
        # Check for forwarded headers
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr

def log_authentication_attempt(email: str, success: bool, auth_type: str = 'passwordless', 
                              failure_reason: Optional[str] = None, **kwargs):
    """Log authentication attempts."""
    log_security_event(
        event_type='authentication_attempt',
        message=f"Authentication {'successful' if success else 'failed'} for {email}",
        auth_type=auth_type,
        success=success,
        failure_reason=failure_reason,
        email=email,
        **kwargs
    )

def log_user_registration(email: str, user_id: str, device_id: str, **kwargs):
    """Log user registration events."""
    log_audit_event(
        action='user_registration',
        resource='user',
        message=f"New user registered: {email}",
        user_id=user_id,
        email=email,
        device_id=device_id,
        **kwargs
    )

def log_device_management(action: str, user_id: str, device_id: str, **kwargs):
    """Log device management events."""
    log_audit_event(
        action=f'device_{action}',
        resource='device',
        message=f"Device {action}: {device_id}",
        user_id=user_id,
        device_id=device_id,
        **kwargs
    )

def log_session_events(action: str, user_id: str, session_id: str, **kwargs):
    """Log session-related events."""
    log_security_event(
        event_type=f'session_{action}',
        message=f"Session {action}: {session_id}",
        user_id=user_id,
        session_id=session_id,
        **kwargs
    )

def log_rate_limit_exceeded(client_id: str, endpoint: str, **kwargs):
    """Log rate limit violations."""
    log_security_event(
        event_type='rate_limit_exceeded',
        message=f"Rate limit exceeded for {client_id} on {endpoint}",
        client_id=client_id,
        endpoint=endpoint,
        **kwargs
    )

def log_security_violation(violation_type: str, details: str, **kwargs):
    """Log security violations."""
    log_security_event(
        event_type='security_violation',
        message=f"Security violation ({violation_type}): {details}",
        violation_type=violation_type,
        details=details,
        **kwargs
    )

def log_database_operation(operation: str, table: str, success: bool, **kwargs):
    """Log database operations."""
    logger.info(f"Database operation: {operation} on {table} {'successful' if success else 'failed'}", extra={
        'operation': operation,
        'table': table,
        'success': success,
        **kwargs
    })

def log_crypto_operation(operation: str, success: bool, **kwargs):
    """Log cryptographic operations."""
    logger.info(f"Crypto operation: {operation} {'successful' if success else 'failed'}", extra={
        'operation': operation,
        'success': success,
        **kwargs
    })

def log_email_operation(operation: str, recipient: str, success: bool, **kwargs):
    """Log email operations."""
    logger.info(f"Email operation: {operation} to {recipient} {'successful' if success else 'failed'}", extra={
        'operation': operation,
        'recipient': recipient,
        'success': success,
        **kwargs
    })

# Decorator for logging function calls
def log_function_call(func_name: str = None):
    """Decorator to log function calls with timing."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            name = func_name or func.__name__
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                logger.debug(f"Function {name} completed successfully in {execution_time:.3f}s", extra={
                    'function': name,
                    'execution_time': execution_time,
                    'success': True
                })
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                
                logger.error(f"Function {name} failed after {execution_time:.3f}s: {str(e)}", extra={
                    'function': name,
                    'execution_time': execution_time,
                    'success': False,
                    'exception': str(e)
                })
                
                raise
        
        return wrapper
    return decorator

# Context manager for logging operations
class LoggedOperation:
    """Context manager for logging operations with timing."""
    
    def __init__(self, operation_name: str, **context):
        self.operation_name = operation_name
        self.context = context
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        logger.debug(f"Starting operation: {self.operation_name}", extra={
            'operation': self.operation_name,
            **self.context
        })
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        execution_time = time.time() - self.start_time
        
        if exc_type is None:
            logger.debug(f"Operation {self.operation_name} completed successfully in {execution_time:.3f}s", extra={
                'operation': self.operation_name,
                'execution_time': execution_time,
                'success': True,
                **self.context
            })
        else:
            logger.error(f"Operation {self.operation_name} failed after {execution_time:.3f}s: {str(exc_val)}", extra={
                'operation': self.operation_name,
                'execution_time': execution_time,
                'success': False,
                'exception': str(exc_val),
                **self.context
            }) 