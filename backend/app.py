from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import config
from database.models import db
from database.db_operations import (
    add_user, get_user_by_email, add_device, get_device_by_public_key,
    update_device_last_used, get_user_devices, remove_device, add_session, add_auth_log
)
import json
 # Import base64 at the very beginning
import base64
import redis
from utils.security import generate_nonce
import jwt
from datetime import datetime, timedelta
import random
import string

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import binascii
import traceback
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import uuid
from database.models import Session, AuthLog
from utils.email_utils import send_notification_email
from mail import mail
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
from flask_talisman import Talisman
from database.models import Device

# Import new security modules
from utils.validation import (
    validate_request_schema, sanitize_inputs, InputValidator,
    REGISTRATION_SCHEMA, AUTH_CHALLENGE_SCHEMA, AUTH_VERIFY_SCHEMA,
    DEVICE_ADD_SCHEMA, RECOVERY_SCHEMA, RECOVERY_COMPLETE_SCHEMA
)
from utils.rate_limiting import (
    create_rate_limiter, rate_limit_exceeded_handler, get_client_identifier,
    auth_rate_limit, registration_rate_limit, recovery_rate_limit,
    device_management_rate_limit, session_rate_limit,
    AdvancedRateLimiter
)
from utils.security_headers import (
    SecurityHeaders, security_headers_middleware, validate_api_security
)
from utils.error_handler import (
    handle_errors, ECCError, ValidationError, AuthenticationError, 
    AuthorizationError, NotFoundError, RateLimitError, DatabaseError,
    CryptoError, EmailError, SessionError, error_response, validation_error,
    not_found_error, authentication_error, authorization_error
)
from utils.enhanced_validation import EnhancedValidator
from utils.logging_config import LoggingConfig
from utils.logging_middleware import RequestLoggingMiddleware, log_authentication_attempt, log_user_registration, log_device_management, log_session_events, log_rate_limit_exceeded, log_security_violation, log_database_operation, log_crypto_operation, log_email_operation
from api_documentation import create_api_documentation, generate_api_spec, get_api_endpoints
from monitoring_system import (
    get_comprehensive_health_status, get_metrics_history, 
    record_request_metric, update_session_metrics, update_user_metrics
)
from database_optimization import (
    get_database_optimization_report, record_database_query,
    generate_index_script, get_optimization_score
)
from performance_optimizer import PerformanceOptimizer, performance_monitor
from api_response_optimizer import ResponseOptimizationMiddleware
from crypto.ecdh_handler import (
    derive_shared_secret, derive_session_keys, generate_ephemeral_keypair,
    serialize_public_key, deserialize_public_key, validate_key_compatibility,
    create_session_context
)

# AES-GCM encryption/decryption utilities

def derive_aes_key_from_shared_secret(shared_secret: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    return digest.finalize()

def aes_gcm_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag

def aes_gcm_decrypt(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

app = Flask(__name__)
CORS(app, 
     origins=["http://localhost:3000"], 
     supports_credentials=True,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"],  
     expose_headers=["Content-Type", "Authorization"]
)

# Load configuration based on environment
config_name = os.environ.get('FLASK_ENV', 'development')
app.config.from_object(config[config_name])

# Initialize logging system
logging_config = LoggingConfig(app_name='ecc_mfa', log_dir='logs')
logging_config.setup_logging()

# Initialize request logging middleware
request_logging = RequestLoggingMiddleware(app)

# Initialize request middleware for enhanced tracking
from utils.request_middleware import init_request_middleware
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
    from flask_limiter import Limiter
    limiter = Limiter(key_func=get_remote_address)
    limiter.init_app(app)

# Initialize advanced rate limiter for monitoring
try:
    advanced_rate_limiter = AdvancedRateLimiter(redis_client)
except Exception as e:
    # Create a mock advanced rate limiter
    class MockAdvancedRateLimiter:
        def record_auth_failure(self, client_id): pass
        def record_auth_success(self, client_id): pass
        def check_suspicious_activity(self, client_id): return False
    advanced_rate_limiter = MockAdvancedRateLimiter()

# Initialize database
db.init_app(app)

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
def handle_validation_error(error):
    """Handle validation errors with enhanced response."""
    from utils.enhanced_error_handler import handle_validation_error as handle_val_error
    return handle_val_error(error)

@app.errorhandler(AuthenticationError)
def handle_authentication_error(error):
    """Handle authentication errors with enhanced response."""
    from utils.enhanced_error_handler import handle_authentication_error as handle_auth_error
    return handle_auth_error(error)

@app.errorhandler(AuthorizationError)
def handle_authorization_error(error):
    """Handle authorization errors with enhanced response."""
    from utils.enhanced_error_handler import handle_authorization_error as handle_authz_error
    return handle_authz_error(error)

@app.errorhandler(NotFoundError)
def handle_not_found_error(error):
    """Handle not found errors with enhanced response."""
    from utils.enhanced_error_handler import handle_not_found_error as handle_nf_error
    return handle_nf_error(error)

@app.errorhandler(RateLimitError)
def handle_rate_limit_error(error):
    """Handle rate limit errors with enhanced response."""
    from utils.enhanced_error_handler import handle_rate_limit_error as handle_rl_error
    return handle_rl_error(error)

@app.errorhandler(ECCError)
def handle_ecc_error(error):
    """Handle ECC errors with enhanced response."""
    from utils.enhanced_error_handler import handle_generic_exception
    return handle_generic_exception(error)

@app.errorhandler(Exception)
def handle_generic_exception(error):
    """Handle generic exceptions with enhanced response."""
    from utils.enhanced_error_handler import handle_generic_exception as handle_gen_error
    return handle_gen_error(error)

mail.init_app(app)

def raw_to_der(raw_sig):
    r = int.from_bytes(raw_sig[:32], byteorder='big')
    s = int.from_bytes(raw_sig[32:], byteorder='big')
    return encode_dss_signature(r, s)

@app.route('/health', methods=['GET'])
def health_check():
    """Enhanced health check endpoint."""
    try:
        health_data = get_comprehensive_health_status()
        
        # Return simplified health status for backward compatibility
        return jsonify({
            'status': health_data['overall'],
            'database': health_data['services']['database']['status'],
            'redis': health_data['services']['redis']['status'],
            'rate_limiting': health_data['services']['rate_limiting']['status'],
            'timestamp': health_data['timestamp'],
            'version': health_data['version'],
            'check_duration_ms': health_data['check_duration_ms']
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/security', methods=['GET'])
def security_info():
    """Get security configuration information."""
    from utils.security_headers import get_security_report
    
    try:
        security_report = get_security_report()
        
        # Remove sensitive information for public endpoint
        public_report = {
            'environment': security_report['environment'],
            'security_headers_count': len(security_report['security_headers']),
            'csp_validation': security_report['csp_validation'],
            'hsts_enabled': 'Strict-Transport-Security' in security_report['hsts_config'],
            'recommendations': security_report['recommendations']
        }
        
        return jsonify(public_report), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to get security information',
            'message': str(e)
        }), 500

@app.route('/logs/stats', methods=['GET'])
def get_log_statistics():
    """Get logging statistics."""
    from utils.logging_config import get_log_stats
    
    try:
        stats = get_log_stats()
        return jsonify(stats), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to get log statistics',
            'message': str(e)
        }), 500

@app.route('/api/docs', methods=['GET'])
def api_documentation():
    """Serve API documentation."""
    return api_docs.doc()

@app.route('/api/spec', methods=['GET'])
def api_specification():
    """Get OpenAPI specification."""
    try:
        spec = generate_api_spec()
        return jsonify(spec), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to generate API specification',
            'message': str(e)
        }), 500

@app.route('/api/endpoints', methods=['GET'])
def api_endpoints():
    """Get list of all API endpoints."""
    try:
        endpoints = get_api_endpoints()
        return jsonify({
            'endpoints': endpoints,
            'total_endpoints': sum(len(v) for v in endpoints.values()),
            'categories': list(endpoints.keys())
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get API endpoints',
            'message': str(e)
        }), 500

@app.route('/api/monitoring/health/comprehensive', methods=['GET'])
def comprehensive_health_check():
    """Get comprehensive health status including all metrics."""
    try:
        health_data = get_comprehensive_health_status()
        return jsonify(health_data), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get comprehensive health status',
            'message': str(e)
        }), 500

@app.route('/api/monitoring/metrics/history', methods=['GET'])
def get_metrics_history_endpoint():
    """Get historical metrics data."""
    try:
        history = get_metrics_history()
        return jsonify({
            'metrics_history': history,
            'total_records': len(history),
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get metrics history',
            'message': str(e)
        }), 500

@app.route('/api/monitoring/performance', methods=['GET'])
def get_performance_report():
    """Get performance monitoring report."""
    try:
        from monitoring_system import performance_monitor
        report = performance_monitor.get_performance_report()
        return jsonify(report), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get performance report',
            'message': str(e)
        }), 500

@app.route('/api/monitoring/system/status', methods=['GET'])
def get_system_status():
    """Get real-time system status."""
    try:
        from monitoring_system import system_metrics
        metrics = system_metrics.collect_system_metrics()
        return jsonify({
            'system_status': metrics,
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get system status',
            'message': str(e)
        }), 500

@app.route('/api/database/optimization/report', methods=['GET'])
def get_database_optimization_report_endpoint():
    """Get comprehensive database optimization report."""
    try:
        report = get_database_optimization_report()
        return jsonify(report), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get database optimization report',
            'message': str(e)
        }), 500

@app.route('/api/database/optimization/score', methods=['GET'])
def get_database_optimization_score():
    """Get current database optimization score."""
    try:
        score = get_optimization_score()
        return jsonify({
            'optimization_score': score,
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get optimization score',
            'message': str(e)
        }), 500

@app.route('/api/database/optimization/indexes', methods=['GET'])
def get_index_optimization_script():
    """Get SQL script for recommended indexes."""
    try:
        script = generate_index_script()
        return jsonify({
            'index_script': script,
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to generate index script',
            'message': str(e)
        }), 500

@app.route('/api/performance/optimize', methods=['POST'])
def run_performance_optimization():
    """Run comprehensive performance optimization."""
    try:
        optimizer = PerformanceOptimizer()
        results = optimizer.run_comprehensive_optimization()
        
        return jsonify({
            'status': 'success',
            'message': 'Performance optimization completed',
            'results': results
        }), 200
    except Exception as e:
        return jsonify({
            'error': {
                'code': 'optimization_error',
                'message': 'Failed to run performance optimization',
                'details': str(e)
            }
        }), 500

@app.route('/api/performance/stats', methods=['GET'])
def get_performance_stats():
    """Get current performance statistics."""
    try:
        stats = performance_monitor.get_performance_stats()
        return jsonify({
            'status': 'success',
            'message': 'Performance statistics retrieved',
            'stats': stats
        }), 200
    except Exception as e:
        return jsonify({
            'error': {
                'code': 'stats_error',
                'message': 'Failed to get performance statistics',
                'details': str(e)
            }
        }), 500

@app.route('/api/performance/cache/clear', methods=['POST'])
def clear_performance_cache():
    """Clear performance cache."""
    try:
        optimizer = PerformanceOptimizer()
        optimizer.redis_client.flushdb()
        return jsonify({
            'status': 'success',
            'message': 'Performance cache cleared'
        }), 200
    except Exception as e:
        return jsonify({
            'error': {
                'code': 'cache_error',
                'message': 'Failed to clear performance cache',
                'details': str(e)
            }
        }), 500

@app.route('/register', methods=['POST'])
@registration_rate_limit()
@validate_request_schema(
    required_fields=REGISTRATION_SCHEMA['required_fields'],
    optional_fields=REGISTRATION_SCHEMA['optional_fields']
)
@sanitize_inputs()
@validate_api_security()
def register():
    """Register a new user (first-time registration only)."""
    try:
        # Get validated data from request context
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        public_key_pem = InputValidator.validate_public_key(data['public_key_pem'])
        device_name = data.get('device_name', 'Unknown Device')
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        
        # Check if user already exists
        user = get_user_by_email(email)
        if user:
            # SECURITY FIX: Prevent existing users from registering
            # Record failure for rate limiting
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({
                'error': 'User already registered.',
                'message': 'An account with this email already exists. Please use the authentication flow to sign in.',
                'code': 'USER_ALREADY_EXISTS'
            }), 409
        else:
            # Create new user with first device
            user_id, device_id = add_user(email, public_key_pem.encode('utf-8'), device_name)
            
            # Generate and send verification code for first-time users
            verification_code = generate_verification_code()
            redis_client.setex(f'email_verification:{email}', 600, verification_code)
            
            send_notification_email(
                subject="Welcome to ECC Passwordless MFA! Please verify your email",
                recipient=email,
                body=f"""Welcome to ECC Passwordless MFA!

Your verification code is: {verification_code}

Please enter this code to complete your registration. This code will expire in 10 minutes.

After verification, you'll be able to authenticate without needing verification codes for future logins.

Best regards,
ECC Passwordless MFA Team"""
            )
            return jsonify({
                'message': 'User registered successfully. Please check your email for verification code.', 
                'device_id': device_id,
                'requires_verification': True
            }), 201
            
    except Exception as e:
        # Record failure for rate limiting
        client_id = get_client_identifier()
        advanced_rate_limiter.record_auth_failure(client_id)
        raise e

@app.route('/auth/challenge', methods=['POST'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=AUTH_CHALLENGE_SCHEMA['required_fields'],
    optional_fields=AUTH_CHALLENGE_SCHEMA['optional_fields']
)
@sanitize_inputs()
@validate_api_security()
def auth_challenge():
    """Generate authentication challenge for user."""
    try:
        # Get validated data from request context
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        
        user = get_user_by_email(email)
        if not user:
            # Record failure for rate limiting
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'User not found.'}), 404
        
        # SECURITY FIX: Check if user's email is verified before allowing authentication
        if not user.email_verified:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({
                'error': 'Email not verified.',
                'message': 'Please verify your email address before authenticating. Check your email for the verification code.',
                'code': 'EMAIL_NOT_VERIFIED'
            }), 403
        
        nonce = generate_nonce()
        redis_client.setex(f'auth_nonce:{email}', 300, nonce)  # 5 min expiry
        
        return jsonify({'nonce': nonce}), 200
        
    except Exception as e:
        # Record failure for rate limiting
        client_id = get_client_identifier()
        advanced_rate_limiter.record_auth_failure(client_id)
        raise e

@app.route('/auth/verify', methods=['POST'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=AUTH_VERIFY_SCHEMA['required_fields'],
    optional_fields=AUTH_VERIFY_SCHEMA['optional_fields']
)
@sanitize_inputs()
@validate_api_security()
def auth_verify():
    """Verify authentication signature and establish secure session."""
    try:
        # Get validated data from request context
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        signature = InputValidator.validate_signature(data['signature'])
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        
        user = get_user_by_email(email)
        if not user:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'User not found.'}), 404
        
        # SECURITY FIX: Check if user's email is verified before allowing authentication
        if not user.email_verified:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({
                'error': 'Email not verified.',
                'message': 'Please verify your email address before authenticating. Check your email for the verification code.',
                'code': 'EMAIL_NOT_VERIFIED'
            }), 403
        
        nonce = redis_client.get(f'auth_nonce:{email}')
        if not nonce:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'Challenge expired or not found.'}), 400
        
        # Handle Redis response (could be bytes or string depending on Redis configuration)
        if isinstance(nonce, bytes):
            nonce = nonce.decode('utf-8')
        
       
        
        try:
            # Decode signature
            signature_bytes = base64.b64decode(signature)
            
            # Get user devices
            devices = get_user_devices(user.user_id)
            if not devices:
                advanced_rate_limiter.record_auth_failure(client_id)
                return jsonify({'error': 'No devices found for user.'}), 404
            
            # Check if device_id was provided in the request
            device_id = data.get('device_id')
            if device_id:
                # Find the specific device
                device = next((d for d in devices if d.device_id == device_id), None)
            else:
                device = None
            
            # Try to verify signature with all devices until one works
            signature_verified = False
            working_device = None
            
            # Determine which devices to try
            devices_to_try = [device] if device else devices
            
            for i, dev in enumerate(devices_to_try):
                try:
                    # Load public key from this device
                    public_key = deserialize_public_key(dev.public_key)
                    
                    # Prepare signature for verification
                    if len(signature_bytes) == 64:
                        # Raw signature (r + s concatenated), convert to DER
                        r = int.from_bytes(signature_bytes[:32], byteorder='big')
                        s = int.from_bytes(signature_bytes[32:], byteorder='big')
                        der_sig = encode_dss_signature(r, s)
                    else:
                        # Already DER signature
                        der_sig = signature_bytes
                    
                    # Attempt verification
                    public_key.verify(der_sig, nonce.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
                    signature_verified = True
                    working_device = dev
                    break
                    
                except Exception as verify_error:
                    continue
            
            if not signature_verified:
                
                # Check if this is a returning user who needs email verification
                # If signature verification fails but user exists, they might need email verification
                # A first-time user would have no devices, a returning user would have devices
                is_first_time_user = len(devices) == 0
                
                if not is_first_time_user:
                    # This is a returning user - check if they have verified their email recently
                    email_verified = redis_client.get(f'email_verified:{email}')
                    # Handle Redis response (could be bytes or string)
                    if isinstance(email_verified, bytes):
                        email_verified = email_verified.decode('utf-8')
                    
                    # If email was recently verified, allow authentication even if signature fails
                    if email_verified and email_verified == 'true':
                        # Find any device for this user to use for authentication
                        if devices:
                            device = devices[0]  # Use the first available device
                            
                            # Update device and user
                            update_device_last_used(device.device_id)
                            user.last_login = datetime.utcnow()
                            db.session.commit()
                            
                            # Create session
                            session_id = str(uuid.uuid4())
                            expires_at = datetime.utcnow() + timedelta(minutes=5)  # Changed from hours=1 to minutes=5 for testing
                            session = add_session(session_id, user.user_id, device.device_id, expires_at)
                            
                            # Enhanced ECDH Key Exchange with perfect forward secrecy
                            server_ecdh_private_key, server_ecdh_public_key = generate_ephemeral_keypair()
                            server_ecdh_public_pem = serialize_public_key(server_ecdh_public_key)
                            
                            # Store server's ECDH private key in Redis
                            server_ecdh_private_pem = server_ecdh_private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                            )
                            redis_client.setex(f'ecdh_privkey:{session_id}', 300, server_ecdh_private_pem.decode('utf-8'))  # Changed from 3600 to 300 seconds (5 minutes) for testing
                            
                            # Log successful authentication
                            add_auth_log(
                                user_id=user.user_id,
                                device_id=device.device_id,
                                event_type='login_success',
                                ip_address=request.remote_addr,
                                user_agent=request.headers.get('User-Agent'),
                                success=True
                            )
                            
                            # Mark user as having a recent successful login (24 hours)
                            redis_client.setex(f'recent_login:{email}', 86400, 'true')
                            
                            # Generate JWT token
                            payload = {
                                'user_id': user.user_id,
                                'email': user.email,
                                'device_id': device.device_id,
                                'exp': expires_at,
                                'session_id': session_id
                            }
                            token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
                            
                            # Clean up nonce
                            redis_client.delete(f'auth_nonce:{email}')
                            
                            # Record successful authentication
                            advanced_rate_limiter.record_auth_success(client_id)
                            
                            return jsonify({
                                'token': token, 
                                'server_ecdh_public_key': server_ecdh_public_pem,
                                'session_id': session_id
                            }), 200
                        else:
                            raise Exception("No devices found for user")
                    
                    # Only require verification if they haven't verified recently (within 24 hours)
                    # This prevents constant verification requests for legitimate users
                    if not email_verified:
                        # Check if they have a recent successful login (within 24 hours)
                        # If they do, don't require verification
                        recent_login = redis_client.get(f'recent_login:{email}')
                        
                        # Always allow email verification when signature verification fails
                        # This ensures users can still authenticate even if their keys are mismatched
                        
                        # Send verification code and require verification
                        verification_code = generate_verification_code()
                        redis_client.setex(f'email_verification:{email}', 600, verification_code)
                        
                        send_notification_email(
                            subject="Your ECC Passwordless MFA Verification Code",
                            recipient=email,
                            body=f"""Your verification code is: {verification_code}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
ECC Passwordless MFA Team"""
                        )
                        
                        return jsonify({
                            'error': 'Email verification required.',
                            'requires_verification': True,
                            'message': 'Please check your email for verification code.'
                        }), 403
                    else:
                        pass
                
                # If we reach here, either it's a first-time user or they don't need verification
                raise Exception("Signature verification failed with all available devices")
            
            # Use the working device for the rest of the authentication
            device = working_device
            
            # Use the working device for the rest of the authentication
            device = working_device
            
            # Update device and user
            update_device_last_used(device.device_id)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Create session
            session_id = str(uuid.uuid4())
            expires_at = datetime.utcnow() + timedelta(minutes=5)
            session = add_session(session_id, user.user_id, device.device_id, expires_at)
            
            # Enhanced ECDH Key Exchange with perfect forward secrecy
            server_ecdh_private_key, server_ecdh_public_key = generate_ephemeral_keypair()
            server_ecdh_public_pem = serialize_public_key(server_ecdh_public_key)
            
            # Store server's ECDH private key in Redis
            server_ecdh_private_pem = server_ecdh_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            redis_client.setex(f'ecdh_privkey:{session_id}', 300, server_ecdh_private_pem.decode('utf-8'))
            
            # Log successful authentication
            add_auth_log(
                user_id=user.user_id,
                device_id=device.device_id,
                event_type='login_success',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=True
            )
            
            # Mark user as having a recent successful login (24 hours)
            redis_client.setex(f'recent_login:{email}', 86400, 'true')
            
            # Generate JWT token
            payload = {
                'user_id': user.user_id,
                'email': user.email,
                'device_id': device.device_id,
                'exp': expires_at,
                'session_id': session_id
            }
            token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
            
            # Clean up nonce
            redis_client.delete(f'auth_nonce:{email}')
            
            # Record successful authentication
            advanced_rate_limiter.record_auth_success(client_id)
            
            # Send notification emails
            try:
                send_notification_email(
                    subject="Login Alert",
                    recipient=email,
                    body="You have successfully logged in to ECC MFA."
                )
                send_notification_email(
                    subject="New Login to Your Account",
                    recipient=email,
                    body=f"A new login to your ECC Passwordless MFA account was detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}. If this wasn't you, please contact support."
                )
            except Exception as e:
                pass
            
            return jsonify({
                'token': token, 
                'server_ecdh_public_key': server_ecdh_public_pem,
                'session_id': session_id
            }), 200
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            
            # Record authentication failure
            advanced_rate_limiter.record_auth_failure(client_id)
            
            # Log failed authentication
            user_id = user.user_id if 'user' in locals() and user else None
            device_id = device.device_id if 'device' in locals() and device else None
            try:
                add_auth_log(
                    user_id=user_id,
                    device_id=device_id,
                    event_type='login_failure',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=Falses
                )
            except Exception as log_err:
                pass
            
            return jsonify({'error': f'Authentication failed: {str(e)}'}), 500
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        
        # Record failure for rate limiting
        client_id = get_client_identifier()
        advanced_rate_limiter.record_auth_failure(client_id)
        raise e

@app.route('/profile', methods=['GET'])
@handle_errors
def get_profile():
    """Get user profile information."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        raise AuthenticationError('Authorization header required.', auth_type='missing_header')

    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        email = payload.get('email')

        if not user_id or not email:
            raise AuthenticationError('Invalid token.', auth_type='invalid_payload')

        user = get_user_by_email(email)
        if not user:
            raise NotFoundError('User not found.', resource_type='user', resource_id=email)

        # Format last_login for display
        last_login = None
        if user.last_login:
            last_login = user.last_login.strftime('%Y-%m-%d %H:%M:%S UTC')

        return jsonify({
            'email': user.email,
            'last_login': last_login,
            'created_at': user.registration_date.strftime('%Y-%m-%d %H:%M:%S UTC') if user.registration_date else None
        }), 200

    except jwt.ExpiredSignatureError:
        raise AuthenticationError('Token expired.', auth_type='expired_token')
    except jwt.InvalidTokenError:
        raise AuthenticationError('Invalid token.', auth_type='invalid_token')

@app.route('/session/ecdh', methods=['POST'])
def session_ecdh():
    """Receive client's ECDH public key, derive shared secret, and store it for the session."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        data = request.get_json()
        client_ecdh_public_pem = data.get('client_ecdh_public_key')
        if not client_ecdh_public_pem:
            return jsonify({'error': 'client_ecdh_public_key is required.'}), 400
        # Retrieve server's ECDH private key from Redis
        server_ecdh_private_pem = redis_client.get(f'ecdh_privkey:{session_id}')
        if not server_ecdh_private_pem:
            return jsonify({'error': 'Server ECDH private key not found or expired.'}), 400
        
        # Handle Redis response (could be bytes or string)
        if isinstance(server_ecdh_private_pem, bytes):
            server_ecdh_private_pem = server_ecdh_private_pem.decode('utf-8')
        
        from cryptography.hazmat.primitives import serialization
        from crypto.ecdh_handler import derive_shared_secret
        # Load server's ECDH private key
        server_ecdh_private_key = serialization.load_pem_private_key(
            server_ecdh_private_pem.encode('utf-8'), password=None
        )
        # Load client's ECDH public key
        client_ecdh_public_key = serialization.load_pem_public_key(
            client_ecdh_public_pem.encode('utf-8')
        )
        # Derive shared secret
        shared_secret = derive_shared_secret(server_ecdh_private_key, client_ecdh_public_key)
        # Store shared secret in Redis (base64 encoded)
        import base64
        shared_secret_b64 = base64.b64encode(shared_secret).decode('utf-8')
        redis_client.setex(f'session_secret:{session_id}', 300, shared_secret_b64)  # Changed from 3600 to 300 seconds (5 minutes) for testing
        return jsonify({'message': 'Shared secret established.'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to establish shared secret: {str(e)}'}), 500

@app.route('/session/secure-data', methods=['POST'])
def session_secure_data():
    """Accepts encrypted payload, decrypts using session's shared secret, and returns encrypted response."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        data = request.get_json()
        ciphertext_b64 = data.get('ciphertext')
        iv_b64 = data.get('iv')
        if not ciphertext_b64 or not iv_b64:
            return jsonify({'error': 'ciphertext and iv are required.'}), 400
        # Retrieve shared secret from Redis
        shared_secret_b64 = redis_client.get(f'session_secret:{session_id}')
        if not shared_secret_b64:
            return jsonify({'error': 'Session shared secret not found.'}), 400
        
        # Handle Redis response (could be bytes or string)
        if isinstance(shared_secret_b64, bytes):
            shared_secret_b64 = shared_secret_b64.decode('utf-8')
        
        shared_secret = base64.b64decode(shared_secret_b64)
        aes_key = derive_aes_key_from_shared_secret(shared_secret)
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        # Split last 16 bytes as tag, rest as ciphertext
        if len(ciphertext) < 16:
            return jsonify({'error': 'Ciphertext too short for tag.'}), 400
        tag = ciphertext[-16:]
        ct = ciphertext[:-16]
        # Decrypt
        try:
            plaintext = aes_gcm_decrypt(ct, aes_key, iv, tag)
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
        # Demo: echo the plaintext back, uppercased
        response_plaintext = plaintext.decode('utf-8').upper().encode('utf-8')
        # Encrypt response
        response_iv = os.urandom(12)
        response_ciphertext, response_tag = aes_gcm_encrypt(response_plaintext, aes_key, response_iv)
        # Append tag to ciphertext and return as one field
        resp_full_ciphertext = response_ciphertext + response_tag
        return jsonify({
            'ciphertext': base64.b64encode(resp_full_ciphertext).decode('utf-8'),
            'iv': base64.b64encode(response_iv).decode('utf-8')
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to process secure data: {str(e)}'}), 500

@app.route('/session/send-secure-message', methods=['POST'])
def send_secure_message():
    """Send an encrypted message to another user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        sender_user_id = payload.get('user_id')
        sender_email = payload.get('email')
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        
        data = request.get_json()
        recipient_email = data.get('recipient_email')
        encrypted_message = data.get('encrypted_message')
        message_iv = data.get('message_iv')
        message_id = data.get('message_id')  # Get message_id from frontend
        
        if not recipient_email or not encrypted_message or not message_iv or not message_id:
            return jsonify({'error': 'recipient_email, encrypted_message, message_iv, and message_id are required.'}), 400
        
        # Validate recipient email
        recipient_email = InputValidator.validate_email(recipient_email)
        
        # Check if recipient exists
        recipient_user = get_user_by_email(recipient_email)
        if not recipient_user:
            return jsonify({'error': 'Recipient not found.'}), 404
        
        # Check if sender is trying to send to themselves
        if sender_email == recipient_email:
            return jsonify({'error': 'Cannot send message to yourself.'}), 400
        
        # Store the encrypted message in Redis with recipient's email as key
        # The message will be encrypted with the sender's session key, so only the sender can decrypt it
        # The recipient will need to establish their own session to read it
        message_data = {
            'sender_email': sender_email,
            'sender_user_id': sender_user_id,
            'encrypted_message': encrypted_message,
            'message_iv': message_iv,
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': session_id,  # This helps identify which session encrypted the message
            'message_id': message_id # Store the message_id
        }
        
        # Store with 24-hour expiry
        message_key = f'secure_message:{recipient_email}:{message_id}' # Use message_id as part of the key
        
        redis_client.setex(message_key, 86400, json.dumps(message_data))
        
        # Send notification email to recipient
        try:
            send_notification_email(
                subject="You have a new secure message",
                recipient=recipient_email,
                body=f"""You have received a new secure message from {sender_email}.

To read this message, please log in to your ECC Passwordless MFA account.

The message will be available for 24 hours.

Best regards,
ECC Passwordless MFA Team"""
            )
        except Exception as e:
            pass
            # Don't fail the whole operation if email fails
        
        return jsonify({
            'message': 'Secure message sent successfully.',
            'message_id': message_id
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to send secure message: {str(e)}'}), 500

@app.route('/session/receive-secure-messages', methods=['GET'])
def receive_secure_messages():
    """Get all encrypted messages for the authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_email = payload.get('email')
        session_id = payload.get('session_id')
        if not session_id:
            return jsonify({'error': 'Invalid token: no session_id.'}), 401
        
        # Get all message keys for this user
        message_keys = redis_client.keys(f'secure_message:{user_email}:*')
        messages = []
        
        for key in message_keys:
            message_data = redis_client.get(key)
            if message_data:
                try:
                    # Parse the stored message data using JSON
                    import json
                    if isinstance(message_data, bytes):
                        message_data = message_data.decode('utf-8')
                    
                    # Try JSON first, fallback to ast.literal_eval for old format
                    try:
                        message_info = json.loads(message_data)
                    except json.JSONDecodeError:
                        import ast
                        message_info = ast.literal_eval(message_data)
                    
                    messages.append({
                        'message_id': message_info['message_id'], # Use message_id from data
                        'sender_email': message_info['sender_email'],
                        'encrypted_message': message_info['encrypted_message'],
                        'message_iv': message_info['message_iv'],
                        'timestamp': message_info['timestamp'],
                        'session_id': message_info['session_id']
                    })
                except Exception as e:
                    continue
        
        # Sort messages by timestamp (newest first)
        messages.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            'messages': messages,
            'count': len(messages)
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to retrieve secure messages: {str(e)}'}), 500

@app.route('/session/delete-secure-message/<message_id>', methods=['DELETE'])
def delete_secure_message(message_id):
    """Delete a specific encrypted message."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_email = payload.get('email')
        if not user_email:
            return jsonify({'error': 'Invalid token.'}), 401
        
        # Find the message by searching through all message keys for this user
        message_keys = redis_client.keys(f'secure_message:{user_email}:*')
        
        for key in message_keys:
            message_data = redis_client.get(key)
            if message_data:
                try:
                    import ast
                    message_info = ast.literal_eval(message_data)
                    if message_info.get('message_id') == message_id:
                        deleted = redis_client.delete(key)
                        if deleted:
                            return jsonify({'message': 'Message deleted successfully.'}), 200
                        else:
                            return jsonify({'error': 'Failed to delete message from storage.'}), 500
                except Exception as e:
                    continue
        
        # If we get here, the message was not found
        return jsonify({'error': 'Message not found.'}), 404
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to delete message: {str(e)}'}), 500

@app.route('/session/update-message-encryption/<message_id>', methods=['PUT'])
def update_message_encryption(message_id):
    """Update the encryption of an existing message (for re-encryption)."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_email = payload.get('email')
        if not user_email:
            return jsonify({'error': 'Invalid token.'}), 401
        
        data = request.get_json()
        new_encrypted_message = data.get('encrypted_message')
        new_message_iv = data.get('message_iv')
        new_message_id = data.get('new_message_id')
        
        if not new_encrypted_message or not new_message_iv or not new_message_id:
            return jsonify({'error': 'encrypted_message, message_iv, and new_message_id are required.'}), 400
        
        # Find the message by searching through all message keys for this user
        message_keys = redis_client.keys(f'secure_message:{user_email}:*')
        message_found = False
        
        for key in message_keys:
            message_data = redis_client.get(key)
            if message_data:
                try:
                    import ast
                    message_info = ast.literal_eval(message_data)
                    if message_info.get('message_id') == message_id:
                        # Found the message, update it
                        message_info['encrypted_message'] = new_encrypted_message
                        message_info['message_iv'] = new_message_iv
                        message_info['message_id'] = new_message_id
                        message_info['timestamp'] = datetime.utcnow().isoformat()
                        
                        # Delete old key and create new one
                        redis_client.delete(key)
                        new_key = f'secure_message:{user_email}:{new_message_id}'
                        redis_client.setex(new_key, 86400, str(message_info))
                        
                        return jsonify({
                            'message': 'Message encryption updated successfully.',
                            'new_message_id': new_message_id
                        }), 200
                except Exception as e:
                    continue
        
        # If we get here, the message was not found
        return jsonify({'error': 'Message not found.'}), 404
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to update message encryption: {str(e)}'}), 500

@app.route('/devices', methods=['GET'])
def get_devices():
    """Get all devices for the authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        devices = get_user_devices(user_id)
        device_list = []
        for device in devices:
            device_list.append({
                'device_id': device.device_id,
                'device_name': device.device_name,
                'created_at': device.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if device.created_at else None,
                'last_used': device.last_used.strftime('%Y-%m-%d %H:%M:%S UTC') if device.last_used else None,
                'is_active': device.is_active
            })
        
        return jsonify({'devices': device_list}), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/devices', methods=['POST'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=['public_key_pem'],
    optional_fields=['device_name']
)
@sanitize_inputs()
@validate_api_security()
def add_new_device():
    """Add a new device for the authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        email = payload.get('email')  # Extract email from JWT token
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        data = request.get_json()
        public_key_pem = data.get('public_key_pem')
        device_name = data.get('device_name', 'Unknown Device')
        
        if not public_key_pem:
            return jsonify({'error': 'public_key_pem is required.'}), 400
        
        # Check if this device is already registered for this user
        existing_device = get_device_by_public_key(public_key_pem.encode('utf-8'))
        if existing_device and existing_device.user_id == user_id:
            return jsonify({'error': 'Device already registered.'}), 400
        
        # Add the new device
        device = add_device(user_id, public_key_pem.encode('utf-8'), device_name)
        
        return jsonify({
            'message': 'Device added successfully.',
            'device_id': device.device_id,
            'device_name': device.device_name
        }), 201
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/devices/<device_id>', methods=['DELETE'])
def remove_user_device(device_id):
    """Remove a device for the authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        # Remove the device (soft delete)
        success = remove_device(device_id, user_id)
        if not success:
            return jsonify({'error': 'Device not found or not authorized.'}), 404
        
        return jsonify({'message': 'Device removed successfully.'}), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/devices/<device_id>/public-key', methods=['GET'])
def get_device_public_key(device_id):
    """Get the public key for a specific device."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required.'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token.'}), 401
        
        # Get the device and verify it belongs to the user
        device = Device.query.filter_by(device_id=device_id, user_id=user_id, is_active=True).first()
        if not device:
            return jsonify({'error': 'Device not found or not authorized.'}), 404
        
        # Return the public key in PEM format
        if isinstance(device.public_key, bytes):
            public_key_pem = device.public_key.decode('utf-8')
        else:
            public_key_pem = device.public_key
        return jsonify({
            'device_id': device.device_id,
            'device_name': device.device_name,
            'public_key_pem': public_key_pem
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401
    except Exception as e:
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/recovery/initiate', methods=['POST'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=['email'],
    optional_fields=[]
)
@sanitize_inputs()
@validate_api_security()
def initiate_recovery():
    """Initiate account recovery process by sending recovery email."""
    try:
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        
        user = get_user_by_email(email)
        if not user:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'User not found.'}), 404
        
        # Generate recovery token
        recovery_token = str(uuid.uuid4())
        recovery_expires = datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
        
        # Store recovery token in Redis with user email (not user_id)
        redis_client.setex(f'recovery_token:{recovery_token}', 86400, user.email)
        
        # Send recovery email
        recovery_url = f"http://localhost:3000/recovery?token={recovery_token}"
        send_notification_email(
            subject="Account Recovery Request",
            recipient=email,
            body=f"""You have requested to recover your ECC Passwordless MFA account.

To proceed with account recovery, click the following link:
{recovery_url}

This link will expire in 24 hours. If you didn't request this recovery, please ignore this email.

For security reasons, this recovery process will require you to:
1. Verify your email address
    2. Generate a new device key
3. Re-authenticate with your new key

If you have any questions, please contact support."""
        )
        
        # Record successful recovery initiation
        advanced_rate_limiter.record_auth_success(client_id)
        
        return jsonify({'message': 'Recovery email sent successfully.'}), 200
        
    except Exception as e:
        # Record failure for rate limiting
        client_id = get_client_identifier()
        advanced_rate_limiter.record_auth_failure(client_id)
        return jsonify({'error': 'Failed to initiate recovery.'}), 500

@app.route('/recovery/verify-token', methods=['POST'])
def verify_recovery_token():
    """Verify recovery token and return user info."""
    data = request.get_json()
    recovery_token = data.get('recovery_token')
    if not recovery_token:
        return jsonify({'error': 'Recovery token is required.'}), 400
    
    # Check if token exists and is valid
    user_email = redis_client.get(f'recovery_token:{recovery_token}')
    if not user_email:
        return jsonify({'error': 'Invalid or expired recovery token.'}), 400
    
    # Handle Redis response (could be bytes or string)
    if isinstance(user_email, bytes):
        user_email = user_email.decode('utf-8')
    
    user = get_user_by_email(user_email) if user_email else None
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    
    return jsonify({
        'email': user.email,
        'user_id': user.user_id,
        'recovery_token': recovery_token
    }), 200

@app.route('/recovery/complete', methods=['POST'])
def complete_recovery():
    """Complete account recovery by registering new device key."""
    data = request.get_json()
    recovery_token = data.get('recovery_token')
    public_key_pem = data.get('public_key_pem')
    device_name = data.get('device_name', 'Recovery Device')
    
    if not recovery_token or not public_key_pem:
        return jsonify({'error': 'Recovery token and public key are required.'}), 400
    
    # Verify recovery token
    user_email = redis_client.get(f'recovery_token:{recovery_token}')
    if not user_email:
        return jsonify({'error': 'Invalid or expired recovery token.'}), 400
    
    # Handle Redis response (could be bytes or string)
    if isinstance(user_email, bytes):
        user_email = user_email.decode('utf-8')
    
    user = get_user_by_email(user_email) if user_email else None
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    
    try:
        # Add new recovery device
        device = add_device(user.user_id, public_key_pem.encode('utf-8'), device_name)
        
        # Delete recovery token
        redis_client.delete(f'recovery_token:{recovery_token}')
        
        # Send recovery completion email
        send_notification_email(
            subject="Account Recovery Completed",
            recipient=user.email,
            body=f"""Your account recovery has been completed successfully.

A new device '{device_name}' has been registered to your account. You can now use this device to authenticate.

For security, we recommend:
1. Reviewing your registered devices
2. Removing any old devices you no longer use
3. Setting up additional devices

If you didn't complete this recovery, please contact support immediately."""
        )
        
        return jsonify({
            'message': 'Account recovery completed successfully.',
            'device_id': device.device_id
        }), 200
    except Exception as e:
        return jsonify({'error': 'Failed to complete recovery.'}), 500

def generate_verification_code():
    """Generate a random 6-digit verification code."""
    return ''.join(random.choices(string.digits, k=6))

@app.route('/email/send-verification', methods=['POST'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=['email'],
    optional_fields=[]
)
@sanitize_inputs()
@validate_api_security()
def send_email_verification():
    """Send a 6-digit verification code to the user's email."""
    try:
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        
        # Check if user exists
        user = get_user_by_email(email)
        if not user:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'User not found.'}), 404
        
        # Generate 6-digit verification code
        verification_code = generate_verification_code()
        
        # Store verification code in Redis with 10-minute expiry
        redis_client.setex(f'email_verification:{email}', 600, verification_code)
        
        # Send verification email
        send_notification_email(
            subject="Your ECC Passwordless MFA Verification Code",
            recipient=email,
            body=f"""Your verification code is: {verification_code}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
ECC Passwordless MFA Team"""
        )
        
        return jsonify({'message': 'Verification code sent successfully.'}), 200
        
    except Exception as e:
        # Record failure for rate limiting
        client_id = get_client_identifier()
        advanced_rate_limiter.record_auth_failure(client_id)
        raise e

@app.route('/email/verify-code', methods=['POST'])
@auth_rate_limit()
@validate_request_schema(
    required_fields=['email', 'verification_code'],
    optional_fields=[]
)
@sanitize_inputs()
@validate_api_security()
def verify_email_code():
    """Verify the 6-digit code sent to the user's email."""
    try:
        data = request.validated_data
        email = InputValidator.validate_email(data['email'])
        verification_code = data['verification_code']
        
        # Get client identifier for rate limiting
        client_id = get_client_identifier()
        
        # Check if user exists
        user = get_user_by_email(email)
        if not user:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'User not found.'}), 404
        
        # Get stored verification code from Redis
        stored_code = redis_client.get(f'email_verification:{email}')
        if not stored_code:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'Verification code expired or not found.'}), 400
        
        # Handle Redis response (could be bytes or string depending on Redis configuration)
        if isinstance(stored_code, bytes):
            stored_code = stored_code.decode('utf-8')
        
        # Verify the code
        if verification_code != stored_code:
            advanced_rate_limiter.record_auth_failure(client_id)
            return jsonify({'error': 'Invalid verification code.'}), 400
        
        # Code is valid - remove it from Redis and mark user as verified
        redis_client.delete(f'email_verification:{email}')
        
        # Mark user as verified in database
        from database.db_operations import mark_user_email_verified
        mark_user_email_verified(user.user_id)
        
        # Store verification status in Redis for 24 hours
        redis_client.setex(f'email_verified:{email}', 86400, 'true')
        
        # Record successful verification
        advanced_rate_limiter.record_auth_success(client_id)
        
        return jsonify({'message': 'Email verification successful. You can now authenticate.'}), 200
        
    except Exception as e:
        # Record failure for rate limiting
        client_id = get_client_identifier()
        advanced_rate_limiter.record_auth_failure(client_id)
        raise e



@app.cli.command('create-db')
def create_db():
    """Create database tables."""
    with app.app_context():
        db.create_all()
    print('Database tables created.')

@app.cli.command('migrate-db')
def migrate_db():
    """Migrate database schema."""
    with app.app_context():
        try:
            # Drop all tables and recreate them (for development)
            db.drop_all()
            db.create_all()
            print('Database migrated successfully.')
        except Exception as e:
            print(f'Migration failed: {e}')
            print('You may need to manually update your database schema.')

@app.cli.command('clear-db')
def clear_db():
    """Clear all data from database tables."""
    with app.app_context():
        try:
            from database.models import User, Device, Session, AuthLog
            
            print('Clearing all data from database...')
            
            # Delete all records from all tables
            Session.query.delete()
            AuthLog.query.delete()
            Device.query.delete()
            User.query.delete()
            
            # Commit the changes
            db.session.commit()
            
            print('✓ All data cleared successfully!')
            print(f'  - Users: {User.query.count()}')
            print(f'  - Devices: {Device.query.count()}')
            print(f'  - Sessions: {Session.query.count()}')
            print(f'  - Auth logs: {AuthLog.query.count()}')
            
        except Exception as e:
            db.session.rollback()

@app.cli.command('db-stats')
def db_stats():
    """Show database statistics."""
    with app.app_context():
        try:
            from database.models import User, Device, Session, AuthLog
            
            print('Database Statistics:')
            print(f'  - Users: {User.query.count()}')
            print(f'  - Devices: {Device.query.count()}')
            print(f'  - Sessions: {Session.query.count()}')
            print(f'  - Auth logs: {AuthLog.query.count()}')
            
        except Exception as e:
            pass

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)