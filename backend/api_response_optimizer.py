#!/usr/bin/env python3
"""
API Response Optimizer for ECC Passwordless MFA.
Implements response compression, pagination, and field selection.
"""

import gzip
import json
from functools import wraps
from typing import Dict, List, Any, Optional, Union
from flask import request, jsonify, Response
from flask_compress import Compress

class APIResponseOptimizer:
    """Optimizes API responses for better performance."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the response optimizer with Flask app."""
        self.app = app
        
        # Initialize Flask-Compress for gzip compression
        Compress(app)
        
        # Configure compression
        app.config['COMPRESS_MIMETYPES'] = [
            'application/json',
            'text/html',
            'text/css',
            'text/xml',
            'application/xml',
            'application/xml+rss',
            'text/javascript'
        ]
        app.config['COMPRESS_LEVEL'] = 6
        app.config['COMPRESS_MIN_SIZE'] = 500
        
        # Register response optimization middleware
        app.after_request(self.optimize_response)
    
    def optimize_response(self, response):
        """Optimize the response with compression and headers."""
        # Add performance headers
        response.headers['X-Response-Optimized'] = 'true'
        response.headers['X-Compression'] = 'gzip'
        
        # Add cache headers for static responses
        if request.endpoint in ['health_check', 'security_info']:
            response.headers['Cache-Control'] = 'public, max-age=300'  # 5 minutes
        
        return response
    
    def paginate_response(self, data: List[Any], page: int = 1, per_page: int = 20, max_per_page: int = 100) -> Dict[str, Any]:
        """Paginate a list of data."""
        # Validate pagination parameters
        page = max(1, page)
        per_page = min(max(1, per_page), max_per_page)
        
        # Calculate pagination
        total_items = len(data)
        total_pages = (total_items + per_page - 1) // per_page
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        # Get page data
        page_data = data[start_idx:end_idx]
        
        return {
            'data': page_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_items': total_items,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            }
        }
    
    def select_fields(self, data: Union[Dict, List[Dict]], fields: List[str]) -> Union[Dict, List[Dict]]:
        """Select specific fields from response data."""
        if isinstance(data, list):
            return [{k: v for k, v in item.items() if k in fields} for item in data]
        elif isinstance(data, dict):
            return {k: v for k, v in data.items() if k in fields}
        return data
    
    def optimize_json_response(self, data: Any, status_code: int = 200, 
                             fields: Optional[List[str]] = None,
                             paginate: bool = False,
                             page: int = 1,
                             per_page: int = 20) -> Response:
        """Create an optimized JSON response."""
        
        # Apply field selection if requested
        if fields and isinstance(data, (dict, list)):
            data = self.select_fields(data, fields)
        
        # Apply pagination if requested and data is a list
        if paginate and isinstance(data, list):
            data = self.paginate_response(data, page, per_page)
        
        # Create response
        response = jsonify(data)
        response.status_code = status_code
        
        # Add optimization headers
        response.headers['X-Response-Optimized'] = 'true'
        if fields:
            response.headers['X-Fields-Selected'] = ','.join(fields)
        if paginate:
            response.headers['X-Paginated'] = 'true'
        
        return response

# Decorators for easy use
def optimize_response(fields: Optional[List[str]] = None, paginate: bool = False):
    """Decorator to optimize API responses."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get pagination parameters from request
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 20, type=int)
            requested_fields = request.args.get('fields', '').split(',') if request.args.get('fields') else None
            
            # Use provided fields or requested fields
            selected_fields = fields or requested_fields
            
            # Call original function
            result = func(*args, **kwargs)
            
            # If result is already a Response, return it
            if isinstance(result, Response):
                return result
            
            # Optimize the response
            optimizer = APIResponseOptimizer()
            return optimizer.optimize_json_response(
                data=result,
                fields=selected_fields,
                paginate=paginate,
                page=page,
                per_page=per_page
            )
        return wrapper
    return decorator

def compress_response(func):
    """Decorator to ensure response compression."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        response = func(*args, **kwargs)
        
        # Add compression headers
        if isinstance(response, Response):
            response.headers['X-Compression'] = 'gzip'
        
        return response
    return wrapper

# Utility functions
def get_pagination_params() -> Dict[str, int]:
    """Get pagination parameters from request."""
    return {
        'page': max(1, request.args.get('page', 1, type=int)),
        'per_page': min(100, max(1, request.args.get('per_page', 20, type=int)))
    }

def get_field_selection() -> Optional[List[str]]:
    """Get field selection from request."""
    fields = request.args.get('fields', '')
    if fields:
        return [f.strip() for f in fields.split(',') if f.strip()]
    return None

# Response optimization middleware
class ResponseOptimizationMiddleware:
    """Middleware for automatic response optimization."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app."""
        self.app = app
        
        # Register after_request handler
        app.after_request(self.optimize_response)
    
    def optimize_response(self, response):
        """Optimize all responses."""
        # Add performance headers
        response.headers['X-Response-Optimized'] = 'true'
        response.headers['X-Compression'] = 'gzip'
        
        # Add cache headers for appropriate endpoints
        if request.endpoint in ['health_check', 'security_info', 'get_log_statistics']:
            response.headers['Cache-Control'] = 'public, max-age=300'
        
        # Add CORS headers for API responses
        if request.endpoint and request.endpoint.startswith('api_'):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        
        return response

# Global optimizer instance
api_optimizer = APIResponseOptimizer() 