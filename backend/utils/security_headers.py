from flask import request, jsonify
from typing import Dict, Any, Optional
import logging
import os

logger = logging.getLogger(__name__)

class SecurityHeaders:
    """Comprehensive security headers configuration for the ECC MFA system."""
    
    # Environment-based CSP configuration
    @staticmethod
    def get_csp_directives():
        """Get CSP directives based on environment."""
        is_production = os.environ.get('FLASK_ENV') == 'production'
        
        if is_production:
            return SecurityHeaders.get_production_csp_directives()
        else:
            return SecurityHeaders.get_development_csp_directives()
    
    @staticmethod
    def get_development_csp_directives():
        """CSP directives for development environment."""
        return {
            'default-src': ["'self'"],
            'script-src': [
                "'self'",
                "'unsafe-inline'",  # Required for React development
                "'unsafe-eval'",    # Required for React development
                "http://localhost:3000",
                "https://localhost:3000",
            ],
            'style-src': [
                "'self'",
                "'unsafe-inline'",  # Required for React styling
                "http://localhost:3000",
                "https://localhost:3000",
            ],
            'img-src': [
                "'self'",
                "data:",
                "https:",
                "http://localhost:3000",
                "https://localhost:3000",
            ],
            'font-src': [
                "'self'",
                "data:",
                "https://fonts.gstatic.com",
                "http://localhost:3000",
                "https://localhost:3000",
            ],
            'connect-src': [
                "'self'",
                "ws://localhost:3000",  # WebSocket for development
                "wss://localhost:3000",  # Secure WebSocket for development
                "http://localhost:5000",  # Backend API
                "https://localhost:5000",  # Secure backend API
                "http://localhost:*",
                "https://localhost:*",
            ],
            'frame-src': ["'none'"],  # Prevent clickjacking
            'object-src': ["'none'"],  # Prevent plugin injection
            'base-uri': ["'self'"],  # Restrict base URI
            'form-action': ["'self'"],  # Restrict form submissions
            'frame-ancestors': ["'none'"],  # Prevent embedding in frames
            'upgrade-insecure-requests': [],  # Upgrade HTTP to HTTPS
            'block-all-mixed-content': [],  # Block mixed content
            'worker-src': ["'self'"],  # Web workers
            'child-src': ["'none'"],  # Child frames
            'manifest-src': ["'self'"],  # Web app manifest
        }
    
    @staticmethod
    def get_production_csp_directives():
        """CSP directives for production environment."""
        return {
            'default-src': ["'self'"],
            'script-src': [
                "'self'",
                "'unsafe-inline'",  # Still needed for React
            ],
            'style-src': [
                "'self'",
                "'unsafe-inline'",  # Still needed for React
            ],
            'img-src': [
                "'self'",
                "data:",
                "https:",
            ],
            'font-src': [
                "'self'",
                "data:",
                "https://fonts.gstatic.com",
            ],
            'connect-src': [
                "'self'",
            ],
            'frame-src': ["'none'"],  # Prevent clickjacking
            'object-src': ["'none'"],  # Prevent plugin injection
            'base-uri': ["'self'"],  # Restrict base URI
            'form-action': ["'self'"],  # Restrict form submissions
            'frame-ancestors': ["'none'"],  # Prevent embedding in frames
            'upgrade-insecure-requests': [],  # Upgrade HTTP to HTTPS
            'block-all-mixed-content': [],  # Block mixed content
            'worker-src': ["'self'"],  # Web workers
            'child-src': ["'none'"],  # Child frames
            'manifest-src': ["'self'"],  # Web app manifest
        }
    
    # Security headers configuration
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'X-DNS-Prefetch-Control': 'off',
        'X-Download-Options': 'noopen',
        'X-Permitted-Cross-Domain-Policies': 'none',
    }
    
    # HSTS configuration
    HSTS_CONFIG = {
        'max_age': 31536000,  # 1 year
        'include_subdomains': True,
        'preload': True
    }
    
    @staticmethod
    def get_csp_header() -> str:
        """
        Generate Content Security Policy header.
        
        Returns:
            str: CSP header value
        """
        csp_directives = SecurityHeaders.get_csp_directives()
        csp_parts = []
        
        for directive, sources in csp_directives.items():
            if sources:
                csp_parts.append(f"{directive} {' '.join(sources)}")
            else:
                csp_parts.append(directive)
        
        return '; '.join(csp_parts)
    
    @staticmethod
    def get_hsts_header() -> str:
        """
        Generate HTTP Strict Transport Security header.
        
        Returns:
            str: HSTS header value
        """
        config = SecurityHeaders.HSTS_CONFIG
        hsts_parts = [f"max-age={config['max_age']}"]
        
        if config['include_subdomains']:
            hsts_parts.append("includeSubDomains")
        
        if config['preload']:
            hsts_parts.append("preload")
        
        return '; '.join(hsts_parts)
    
    @staticmethod
    def add_security_headers(response):
        """
        Add all security headers to response.
        
        Args:
            response: Flask response object
            
        Returns:
            Response: Response with security headers
        """
        try:
            # Add CSP header
            csp_header = SecurityHeaders.get_csp_header()
            response.headers['Content-Security-Policy'] = csp_header
            
            # Add HSTS header (only for HTTPS or in production)
            if request.is_secure or os.environ.get('FLASK_ENV') == 'production':
                response.headers['Strict-Transport-Security'] = SecurityHeaders.get_hsts_header()
            
            # Add other security headers
            for header, value in SecurityHeaders.SECURITY_HEADERS.items():
                response.headers[header] = value
            
            # Add custom security headers for ECC MFA
            response.headers['X-ECC-MFA-Version'] = '1.0.0'
            response.headers['X-ECC-MFA-Security'] = 'enabled'
            response.headers['X-ECC-MFA-Environment'] = os.environ.get('FLASK_ENV', 'development')
            
            # Remove server information headers
            if 'Server' in response.headers:
                del response.headers['Server']
            
            logger.debug(f"Security headers added to response: {dict(response.headers)}")
            
        except Exception as e:
            logger.error(f"Error adding security headers: {str(e)}")
            # Fallback to basic security headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
    
    @staticmethod
    def validate_csp_header(csp_header: str) -> Dict[str, Any]:
        """
        Validate CSP header configuration.
        
        Args:
            csp_header: CSP header value
            
        Returns:
            Dict: Validation results
        """
        validation = {
            'valid': True,
            'warnings': [],
            'recommendations': []
        }
        
        # Check for required directives
        required_directives = ['default-src', 'script-src', 'style-src']
        for directive in required_directives:
            if directive not in csp_header:
                validation['warnings'].append(f"Missing required CSP directive: {directive}")
        
        # Check for unsafe sources
        unsafe_sources = ["'unsafe-inline'", "'unsafe-eval'"]
        for source in unsafe_sources:
            if source in csp_header:
                validation['recommendations'].append(f"Consider removing unsafe source: {source}")
        
        # Check for frame protection
        if "frame-ancestors 'none'" not in csp_header:
            validation['recommendations'].append("Consider adding frame-ancestors 'none' for clickjacking protection")
        
        return validation

def security_headers_middleware():
    """
    Middleware to add security headers to all responses.
    """
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            
            if response is not None:
                response = SecurityHeaders.add_security_headers(response)
            
            return response
        
        return decorated_function
    return decorator

def validate_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate security headers in a request.
    
    Args:
        headers: Request headers
        
    Returns:
        Dict: Validation results
    """
    validation_results = {
        'valid': True,
        'issues': [],
        'recommendations': [],
        'security_score': 100
    }
    
    # Check for required security headers
    required_headers = [
        'User-Agent',
        'Accept',
        'Accept-Language',
        'Accept-Encoding'
    ]
    
    for header in required_headers:
        if header not in headers:
            validation_results['issues'].append(f"Missing required header: {header}")
            validation_results['valid'] = False
            validation_results['security_score'] -= 10
    
    # Check for suspicious headers
    suspicious_headers = [
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Originating-IP',
        'CF-Connecting-IP'
    ]
    
    for header in suspicious_headers:
        if header in headers:
            validation_results['recommendations'].append(f"Verify {header} header: {headers[header]}")
    
    # Check for potential security issues
    if 'User-Agent' in headers:
        user_agent = headers['User-Agent'].lower()
        if 'bot' in user_agent or 'crawler' in user_agent:
            validation_results['recommendations'].append("Bot/crawler detected")
        if 'curl' in user_agent or 'wget' in user_agent:
            validation_results['recommendations'].append("Automated tool detected")
    
    # Check for missing security headers in request
    security_headers_in_request = [
        'X-Requested-With',
        'Origin',
        'Referer'
    ]
    
    for header in security_headers_in_request:
        if header not in headers:
            validation_results['recommendations'].append(f"Consider adding {header} header for CSRF protection")
    
    return validation_results

def log_security_event(event_type: str, details: Dict[str, Any]):
    """
    Log security-related events.
    
    Args:
        event_type: Type of security event
        details: Event details
    """
    logger.warning(f"Security event: {event_type} - {details}")

# Security header validation for specific endpoints
def validate_api_security():
    """
    Validate security requirements for API endpoints.
    """
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Validate request headers
                header_validation = validate_security_headers(dict(request.headers))
                
                if not header_validation['valid']:
                    logger.warning(f"Security header validation failed: {header_validation['issues']}")
                    return jsonify({
                        'error': 'Security validation failed',
                        'details': header_validation['issues'],
                        'code': 'SECURITY_VALIDATION_FAILED'
                    }), 400
                
                # Log security recommendations
                if header_validation['recommendations']:
                    logger.info(f"Security recommendations: {header_validation['recommendations']}")
                
                # Log low security score
                if header_validation['security_score'] < 70:
                    logger.warning(f"Low security score: {header_validation['security_score']}")
                
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Security validation error: {str(e)}")
                # In case of security validation failure, continue without validation
                logger.warning("Continuing without security validation due to error")
                return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def get_security_report() -> Dict[str, Any]:
    """
    Generate a security report for the current configuration.
    
    Returns:
        Dict: Security configuration report
    """
    csp_header = SecurityHeaders.get_csp_header()
    csp_validation = SecurityHeaders.validate_csp_header(csp_header)
    
    return {
        'environment': os.environ.get('FLASK_ENV', 'development'),
        'csp_header': csp_header,
        'csp_validation': csp_validation,
        'security_headers': SecurityHeaders.SECURITY_HEADERS,
        'hsts_config': SecurityHeaders.HSTS_CONFIG,
        'recommendations': [
            "Ensure HTTPS is used in production",
            "Regularly update CSP directives",
            "Monitor security headers in production",
            "Consider implementing Subresource Integrity (SRI)",
            "Regular security audits recommended"
        ]
    } 