"""
API Documentation and OpenAPI/Swagger Specification for ECC Passwordless MFA.
Provides comprehensive API documentation with interactive testing interface.
"""

from flask_restx import Api, Resource, fields, Namespace
from flask import request, jsonify
from functools import wraps
import json
from datetime import datetime
from typing import Dict, Any, Optional

# Create the main API documentation
api = Api(
    title='ECC Passwordless MFA API',
    version='1.0.0',
    description='''
    # ECC Passwordless Multi-Factor Authentication API
    
    This API provides secure, passwordless authentication using Elliptic Curve Cryptography (ECC).
    
    ## Features
    - **Passwordless Authentication**: No passwords required, uses cryptographic keys
    - **Multi-Device Support**: Register and manage multiple devices per user
    - **Secure Key Exchange**: ECDH for secure session establishment
    - **Rate Limiting**: Protection against brute force attacks
    - **Comprehensive Logging**: Full audit trail and security monitoring
    
    ## Authentication
    Most endpoints require JWT authentication. Include the token in the Authorization header:
    ```
    Authorization: Bearer <your-jwt-token>
    ```
    
    ## Security
    - All endpoints use HTTPS in production
    - Comprehensive security headers implemented
    - Rate limiting on sensitive endpoints
    - Input validation and sanitization
    ''',
    doc='/api/docs',
    authorizations={
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'JWT token in format: Bearer <token>'
        }
    },
    security='Bearer',
    contact='ECC MFA Team',
    contact_email='support@ecc-mfa.com',
    contact_url='https://github.com/ecc-mfa',
    license='MIT',
    license_url='https://opensource.org/licenses/MIT'
)

# Create namespaces for different API sections
auth_ns = Namespace('auth', description='Authentication operations')
user_ns = Namespace('user', description='User management operations')
device_ns = Namespace('device', description='Device management operations')
email_ns = Namespace('email', description='Email verification operations')
system_ns = Namespace('system', description='System and health operations')

# Add namespaces to API
api.add_namespace(auth_ns, path='/api/auth')
api.add_namespace(user_ns, path='/api/user')
api.add_namespace(device_ns, path='/api/device')
api.add_namespace(email_ns, path='/api/email')
api.add_namespace(system_ns, path='/api/system')

# Define common response models
error_model = api.model('Error', {
    'error': fields.Boolean(description='Error flag', example=True),
    'code': fields.String(description='Error code', example='VALIDATION_ERROR'),
    'message': fields.String(description='Error message', example='Required field missing'),
    'request_id': fields.String(description='Request ID for tracking', example='uuid-string'),
    'timestamp': fields.String(description='Error timestamp', example='2025-07-30T16:20:34.028834')
})

success_model = api.model('Success', {
    'success': fields.Boolean(description='Success flag', example=True),
    'message': fields.String(description='Success message', example='Operation completed successfully'),
    'request_id': fields.String(description='Request ID for tracking', example='uuid-string'),
    'timestamp': fields.String(description='Response timestamp', example='2025-07-30T16:20:34.028834')
})

# Authentication models
register_model = api.model('Register', {
    'email': fields.String(required=True, description='User email address', example='user@example.com'),
    'public_key_pem': fields.String(required=True, description='Device public key in PEM format', example='-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----'),
    'device_name': fields.String(description='Device name', example='My iPhone')
})

auth_challenge_model = api.model('AuthChallenge', {
    'email': fields.String(required=True, description='User email address', example='user@example.com')
})

auth_verify_model = api.model('AuthVerify', {
    'email': fields.String(required=True, description='User email address', example='user@example.com'),
    'signature': fields.String(required=True, description='Challenge signature', example='hex-signature-string'),
    'device_id': fields.String(required=True, description='Device ID', example='uuid-string')
})

auth_response_model = api.model('AuthResponse', {
    'success': fields.Boolean(description='Authentication success', example=True),
    'token': fields.String(description='JWT access token', example='jwt-token-string'),
    'user_id': fields.String(description='User ID', example='uuid-string'),
    'device_id': fields.String(description='Device ID', example='uuid-string'),
    'expires_in': fields.Integer(description='Token expiration time in seconds', example=3600)
})

# User models
profile_model = api.model('Profile', {
    'email': fields.String(description='User email', example='user@example.com'),
    'last_login': fields.String(description='Last login timestamp', example='2025-07-30 16:20:34 UTC'),
    'created_at': fields.String(description='Account creation timestamp', example='2025-07-30 10:15:22 UTC')
})

# Device models
device_model = api.model('Device', {
    'device_id': fields.String(description='Device ID', example='uuid-string'),
    'device_name': fields.String(description='Device name', example='My iPhone'),
    'public_key_pem': fields.String(description='Device public key', example='-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----'),
    'created_at': fields.String(description='Device registration timestamp', example='2025-07-30 10:15:22 UTC'),
    'last_used': fields.String(description='Last usage timestamp', example='2025-07-30 16:20:34 UTC')
})

add_device_model = api.model('AddDevice', {
    'public_key_pem': fields.String(required=True, description='Device public key in PEM format', example='-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----'),
    'device_name': fields.String(description='Device name', example='My iPad')
})

# Email models
verify_email_model = api.model('VerifyEmail', {
    'email': fields.String(required=True, description='User email address', example='user@example.com'),
    'verification_code': fields.String(required=True, description='6-digit verification code', example='123456')
})

# System models
health_model = api.model('Health', {
    'status': fields.String(description='Overall system status', example='ok'),
    'services': fields.Raw(description='Service health status', example={
        'database': 'healthy',
        'redis': 'healthy',
        'rate_limiting': 'healthy'
    }),
    'timestamp': fields.String(description='Health check timestamp', example='2025-07-30T16:20:34.028834'),
    'version': fields.String(description='API version', example='1.0.0')
})

security_model = api.model('Security', {
    'environment': fields.String(description='Environment', example='development'),
    'security_headers_count': fields.Integer(description='Number of security headers', example=11),
    'csp_validation': fields.Raw(description='Content Security Policy validation'),
    'hsts_enabled': fields.Boolean(description='HSTS enabled', example=False),
    'recommendations': fields.List(fields.String, description='Security recommendations')
})

log_stats_model = api.model('LogStats', {
    'log_directory': fields.String(description='Log directory path', example='/app/logs'),
    'total_size_mb': fields.Float(description='Total log size in MB', example=0.12),
    'files': fields.Raw(description='Log file statistics')
})

# API Documentation Decorators
def api_doc(description: str, responses: Dict[int, str] = None):
    """Decorator to add API documentation to endpoints."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        
        # Add documentation attributes
        wrapper.__doc__ = description
        wrapper.__api_responses__ = responses or {}
        return wrapper
    return decorator

# Authentication endpoints documentation
@auth_ns.route('/register')
class RegisterAPI(Resource):
    @auth_ns.doc('register_user', 
                 description='Register a new user with their first device',
                 responses={
                     201: 'User registered successfully',
                     400: 'Validation error',
                     409: 'User already exists'
                 })
    @auth_ns.expect(register_model)
    @auth_ns.marshal_with(success_model, code=201)
    @api_doc('''
    Register a new user with their first device.
    
    This endpoint creates a new user account and registers their first device.
    The user must provide a valid email address and their device's public key.
    
    **Security Notes:**
    - Email must be unique across the system
    - Public key must be in valid PEM format
    - Rate limiting applies to prevent abuse
    ''')
    def post(self):
        """Register a new user with their first device."""
        pass

@auth_ns.route('/challenge')
class AuthChallengeAPI(Resource):
    @auth_ns.doc('auth_challenge',
                 description='Request authentication challenge',
                 responses={
                     200: 'Challenge generated successfully',
                     404: 'User not found',
                     429: 'Rate limit exceeded'
                 })
    @auth_ns.expect(auth_challenge_model)
    @api_doc('''
    Request an authentication challenge for passwordless login.
    
    This endpoint generates a cryptographic challenge that the user's device
    must sign to prove ownership of the private key.
    
    **Security Notes:**
    - Challenge is cryptographically secure random data
    - Challenge expires after a short time
    - Rate limiting prevents brute force attacks
    ''')
    def post(self):
        """Request authentication challenge."""
        pass

@auth_ns.route('/verify')
class AuthVerifyAPI(Resource):
    @auth_ns.doc('auth_verify',
                 description='Verify authentication challenge',
                 responses={
                     200: 'Authentication successful',
                     400: 'Invalid signature',
                     401: 'Authentication failed',
                     404: 'User or device not found'
                 })
    @auth_ns.expect(auth_verify_model)
    @auth_ns.marshal_with(auth_response_model, code=200)
    @api_doc('''
    Verify the authentication challenge signature.
    
    This endpoint verifies that the user's device correctly signed the
    challenge using their private key, proving device ownership.
    
    **Security Notes:**
    - Signature must be valid for the provided challenge
    - Device must be registered and verified
    - JWT token is issued upon successful verification
    ''')
    def post(self):
        """Verify authentication challenge."""
        pass

# User endpoints documentation
@user_ns.route('/profile')
class ProfileAPI(Resource):
    @user_ns.doc('get_profile',
                 description='Get user profile information',
                 security='Bearer',
                 responses={
                     200: 'Profile retrieved successfully',
                     401: 'Authentication required',
                     404: 'User not found'
                 })
    @user_ns.marshal_with(profile_model, code=200)
    @api_doc('''
    Retrieve the current user's profile information.
    
    This endpoint returns the user's profile data including email,
    last login time, and account creation date.
    
    **Authentication Required:** JWT token in Authorization header
    ''')
    def get(self):
        """Get user profile information."""
        pass

# Device endpoints documentation
@device_ns.route('/')
class DeviceListAPI(Resource):
    @device_ns.doc('list_devices',
                   description='List user devices',
                   security='Bearer',
                   responses={
                       200: 'Devices retrieved successfully',
                       401: 'Authentication required'
                   })
    @device_ns.marshal_list_with(device_model, code=200)
    @api_doc('''
    List all devices registered for the current user.
    
    This endpoint returns a list of all devices associated with
    the authenticated user's account.
    
    **Authentication Required:** JWT token in Authorization header
    ''')
    def get(self):
        """List user devices."""
        pass

@device_ns.route('/add')
class AddDeviceAPI(Resource):
    @device_ns.doc('add_device',
                   description='Add a new device',
                   security='Bearer',
                   responses={
                       201: 'Device added successfully',
                       400: 'Validation error',
                       401: 'Authentication required'
                   })
    @device_ns.expect(add_device_model)
    @device_ns.marshal_with(success_model, code=201)
    @api_doc('''
    Add a new device to the user's account.
    
    This endpoint registers a new device for the authenticated user.
    The device must provide its public key for secure communication.
    
    **Authentication Required:** JWT token in Authorization header
    **Security Notes:**
    - Public key must be in valid PEM format
    - Device name is optional but recommended
    ''')
    def post(self):
        """Add a new device."""
        pass

# Email endpoints documentation
@email_ns.route('/verify')
class VerifyEmailAPI(Resource):
    @email_ns.doc('verify_email',
                  description='Verify email address',
                  responses={
                      200: 'Email verified successfully',
                      400: 'Invalid verification code',
                      404: 'User not found'
                  })
    @email_ns.expect(verify_email_model)
    @email_ns.marshal_with(success_model, code=200)
    @api_doc('''
    Verify a user's email address using a verification code.
    
    This endpoint verifies the user's email address using a 6-digit
    code sent to their email address during registration.
    
    **Security Notes:**
    - Verification code must be exactly 6 digits
    - Code expires after a limited time
    - Rate limiting applies to prevent abuse
    ''')
    def post(self):
        """Verify email address."""
        pass

# System endpoints documentation
@system_ns.route('/health')
class HealthAPI(Resource):
    @system_ns.doc('health_check',
                   description='System health check',
                   responses={
                       200: 'System healthy',
                       503: 'System unhealthy'
                   })
    @system_ns.marshal_with(health_model, code=200)
    @api_doc('''
    Check the overall health of the system.
    
    This endpoint provides information about the system's health status,
    including database connectivity, Redis status, and rate limiting health.
    
    **Use Cases:**
    - Load balancer health checks
    - Monitoring system status
    - Troubleshooting system issues
    ''')
    def get(self):
        """System health check."""
        pass

@system_ns.route('/security')
class SecurityAPI(Resource):
    @system_ns.doc('security_info',
                   description='Security configuration information',
                   responses={
                       200: 'Security information retrieved'
                   })
    @system_ns.marshal_with(security_model, code=200)
    @api_doc('''
    Get security configuration information.
    
    This endpoint provides information about the current security
    configuration, including security headers, CSP settings, and
    security recommendations.
    
    **Use Cases:**
    - Security auditing
    - Configuration verification
    - Compliance checking
    ''')
    def get(self):
        """Get security configuration information."""
        pass

@system_ns.route('/logs/stats')
class LogStatsAPI(Resource):
    @system_ns.doc('log_stats',
                   description='Logging statistics',
                   responses={
                       200: 'Log statistics retrieved',
                       500: 'Failed to retrieve log statistics'
                   })
    @system_ns.marshal_with(log_stats_model, code=200)
    @api_doc('''
    Get logging system statistics.
    
    This endpoint provides information about the logging system,
    including log file sizes, directory information, and total
    log storage usage.
    
    **Use Cases:**
    - Log monitoring
    - Storage management
    - System administration
    ''')
    def get(self):
        """Get logging statistics."""
        pass

# API Documentation Helper Functions
def generate_api_spec() -> Dict[str, Any]:
    """Generate OpenAPI specification."""
    return {
        'openapi': '3.0.0',
        'info': {
            'title': 'ECC Passwordless MFA API',
            'version': '1.0.0',
            'description': 'Secure passwordless authentication using ECC',
            'contact': {
                'name': 'ECC MFA Team',
                'email': 'support@ecc-mfa.com'
            }
        },
        'servers': [
            {
                'url': 'http://localhost:5000',
                'description': 'Development server'
            },
            {
                'url': 'https://api.ecc-mfa.com',
                'description': 'Production server'
            }
        ],
        'components': {
            'securitySchemes': {
                'Bearer': {
                    'type': 'http',
                    'scheme': 'bearer',
                    'bearerFormat': 'JWT'
                }
            }
        }
    }

def get_api_endpoints() -> Dict[str, Any]:
    """Get list of all API endpoints."""
    endpoints = {
        'authentication': {
            'POST /api/auth/register': 'Register new user',
            'POST /api/auth/challenge': 'Request auth challenge',
            'POST /api/auth/verify': 'Verify auth challenge'
        },
        'user_management': {
            'GET /api/user/profile': 'Get user profile'
        },
        'device_management': {
            'GET /api/device/': 'List user devices',
            'POST /api/device/add': 'Add new device'
        },
        'email_verification': {
            'POST /api/email/verify': 'Verify email address'
        },
        'system': {
            'GET /api/system/health': 'System health check',
            'GET /api/system/security': 'Security information',
            'GET /api/system/logs/stats': 'Logging statistics'
        }
    }
    return endpoints

def create_api_documentation():
    """Initialize API documentation."""
    return api 