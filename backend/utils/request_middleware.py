"""
Request Middleware for ECC Passwordless MFA.
Adds request IDs and context for better tracking and debugging.
"""

import uuid
import time
import logging
from datetime import datetime
from typing import Dict, Any
from flask import request, g

logger = logging.getLogger(__name__)

class RequestMiddleware:
    """Middleware to add request context and tracking."""
    
    @staticmethod
    def before_request():
        """Add request context before processing."""
        # Generate unique request ID
        request.request_id = str(uuid.uuid4())
        
        # Add request start time
        g.request_start_time = time.time()
        
        # Log request details
        log_data = {
            "request_id": request.request_id,
            "method": request.method,
            "path": request.path,
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get('User-Agent'),
            "timestamp": datetime.now().isoformat(),
        }
        
        # Add query parameters if present
        if request.args:
            log_data["query_params"] = dict(request.args)
        
        # Add request headers (filter sensitive ones)
        headers = dict(request.headers)
        sensitive_headers = ['authorization', 'cookie', 'x-api-key']
        for header in sensitive_headers:
            if header in headers:
                headers[header] = '[REDACTED]'
        log_data["headers"] = headers
        
        logger.info("Request started", extra=log_data)
    
    @staticmethod
    def after_request(response):
        """Add response context after processing."""
        # Calculate request duration
        if hasattr(g, 'request_start_time'):
            duration = time.time() - g.request_start_time
        else:
            duration = 0
        
        # Add request ID to response headers
        if hasattr(request, 'request_id'):
            response.headers['X-Request-ID'] = request.request_id
        
        # Add response time header
        response.headers['X-Response-Time'] = f"{duration:.3f}s"
        
        # Log response details
        log_data = {
            "request_id": getattr(request, 'request_id', 'unknown'),
            "method": request.method,
            "path": request.path,
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 2),
            "timestamp": datetime.now().isoformat(),
        }
        
        # Log based on status code
        if response.status_code >= 500:
            logger.error("Request completed with server error", extra=log_data)
        elif response.status_code >= 400:
            logger.warning("Request completed with client error", extra=log_data)
        else:
            logger.info("Request completed successfully", extra=log_data)
        
        return response
    
    @staticmethod
    def teardown_request(exception=None):
        """Clean up request context."""
        if exception:
            # Log any unhandled exceptions
            log_data = {
                "request_id": getattr(request, 'request_id', 'unknown'),
                "method": request.method,
                "path": request.path,
                "exception_type": type(exception).__name__,
                "exception_message": str(exception),
                "timestamp": datetime.now().isoformat(),
            }
            logger.error("Unhandled exception in request", extra=log_data)

def init_request_middleware(app):
    """Initialize request middleware for Flask app."""
    app.before_request(RequestMiddleware.before_request)
    app.after_request(RequestMiddleware.after_request)
    app.teardown_request(RequestMiddleware.teardown_request)
    
    logger.info("Request middleware initialized")

def get_request_context() -> Dict[str, Any]:
    """Get current request context."""
    return {
        "request_id": getattr(request, 'request_id', 'unknown'),
        "method": request.method if request else None,
        "path": request.path if request else None,
        "ip_address": request.remote_addr if request else None,
        "user_agent": request.headers.get('User-Agent') if request else None,
        "timestamp": datetime.now().isoformat(),
    } 