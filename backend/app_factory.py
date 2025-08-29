"""
Application Factory for ECC Passwordless MFA.
Creates and configures the Flask application with blueprints.
"""

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from config import config
from database.models import db
from mail import mail
import redis
import os

from blueprints.auth import auth_bp
from blueprints.devices import devices_bp
from blueprints.sessions import sessions_bp
from blueprints.recovery import recovery_bp
from blueprints.monitoring import monitoring_bp
from blueprints.admin import admin_bp

# Import utilities
from utils.rate_limiting import (
    create_rate_limiter, rate_limit_exceeded_handler, AdvancedRateLimiter
)
from utils.logging_config import LoggingConfig
from utils.logging_middleware import RequestLoggingMiddleware
from utils.request_middleware import init_request_middleware
from utils.security_headers import SecurityHeaders
from utils.unified_error_handler import (
    ValidationError, AuthenticationError, AuthorizationError, 
    NotFoundError, RateLimitError, ECCError,
    handle_validation_error, handle_authentication_error, 
    handle_authorization_error, handle_not_found_error,
    handle_rate_limit_error, handle_generic_exception
)
from api_response_optimizer import ResponseOptimizationMiddleware
from api_documentation import create_api_documentation

def create_app(config_name=None):
    """Create and configure the Flask application."""
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config[config_name])
    
    # Initialize CORS
    CORS(app, 
         origins=["http://localhost:3000"], 
         supports_credentials=True,
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         allow_headers=["Content-Type", "Authorization", "X-Requested-With"],  
         expose_headers=["Content-Type", "Authorization"]
    )
    
    # Initialize logging system
    logging_config = LoggingConfig(app_name='ecc_mfa', log_dir='logs')
    logging_config.setup_logging()
    
    # Initialize request logging middleware
    request_logging = RequestLoggingMiddleware(app)
    
    # Initialize request middleware for enhanced tracking
    init_request_middleware(app)
    
    # Initialize response optimization middleware
    response_optimizer = ResponseOptimizationMiddleware(app)
    
    # Initialize API documentation
    api_docs = create_api_documentation()
    api_docs.init_app(app)
    
    # Validate configuration
    if app.config.get('FLASK_ENV') == 'production':
        issues = config[config_name].validate_config()
        if issues:
            print("Configuration issues found:")
            for issue in issues:
                print(f"  - {issue}")
            print("Please fix these issues before starting in production mode.")
    
    # Initialize Redis client
    redis_client = redis.StrictRedis.from_url(app.config['REDIS_URL'], decode_responses=True)
    
    # Initialize enhanced rate limiter
    try:
        limiter = create_rate_limiter(app, redis_client)
    except Exception as e:
        # Fallback to basic rate limiter
        limiter = Limiter(key_func=get_remote_address)
        limiter.init_app(app)
    
    # Initialize advanced rate limiter for monitoring
    try:
        advanced_rate_limiter = AdvancedRateLimiter(redis_client)
        app.extensions['advanced_rate_limiter'] = advanced_rate_limiter
    except Exception as e:
        # Create a mock advanced rate limiter
        class MockAdvancedRateLimiter:
            def record_auth_failure(self, client_id): pass
            def record_auth_success(self, client_id): pass
            def check_suspicious_activity(self, client_id): return False
        advanced_rate_limiter = MockAdvancedRateLimiter()
        app.extensions['advanced_rate_limiter'] = advanced_rate_limiter
    
    # Initialize database
    db.init_app(app)
    
    # Initialize mail
    mail.init_app(app)
    
    # Add Flask-Talisman for security headers and HTTPS enforcement
    Talisman(app, 
             content_security_policy=None,  # We'll handle CSP manually
             force_https=False,  # Disable HTTPS enforcement for testing
             strict_transport_security=False,  # Disable HSTS for testing
             frame_options='DENY')  # Set X-Frame-Options to DENY
    
    # Register rate limit exceeded handler
    app.register_error_handler(429, rate_limit_exceeded_handler)
    
    # Add security headers middleware
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        try:
            return SecurityHeaders.add_security_headers(response)
        except Exception as e:
            # Add basic security headers as fallback
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            return response
    
    # Global error handlers with enhanced error handling
    @app.errorhandler(ValidationError)
    def handle_validation_error_wrapper(error):
        """Handle validation errors with enhanced response."""
        return handle_validation_error(error)
    
    @app.errorhandler(AuthenticationError)
    def handle_authentication_error_wrapper(error):
        """Handle authentication errors with enhanced response."""
        return handle_authentication_error(error)
    
    @app.errorhandler(AuthorizationError)
    def handle_authorization_error_wrapper(error):
        """Handle authorization errors with enhanced response."""
        return handle_authorization_error(error)
    
    @app.errorhandler(NotFoundError)
    def handle_not_found_error_wrapper(error):
        """Handle not found errors with enhanced response."""
        return handle_not_found_error(error)
    
    @app.errorhandler(RateLimitError)
    def handle_rate_limit_error_wrapper(error):
        """Handle rate limit errors with enhanced response."""
        return handle_rate_limit_error(error)
    
    @app.errorhandler(ECCError)
    def handle_ecc_error_wrapper(error):
        """Handle ECC errors with enhanced response."""
        return handle_generic_exception(error)
    
    @app.errorhandler(Exception)
    def handle_generic_exception_wrapper(error):
        """Handle generic exceptions with enhanced response."""
        return handle_generic_exception(error)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(sessions_bp)
    app.register_blueprint(recovery_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(admin_bp)
    
    # Add static file route for Swagger UI (excluded from logging middleware)
    @app.route('/swaggerui/<path:filename>')
    def swagger_ui_static(filename):
        """Serve Swagger UI static files."""
        from flask import send_from_directory
        
        # Get the path to flask-restx static files
        from flask_restx import __path__ as restx_path
        static_path = os.path.join(restx_path[0], 'static')
        
        # Ensure the file exists
        file_path = os.path.join(static_path, filename)
        if not os.path.exists(file_path):
            return "File not found", 404
        
        # Serve the file directly without going through middleware
        return send_from_directory(static_path, filename)
    
    return app
