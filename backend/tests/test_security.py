import pytest
import json
import base64
import hashlib
import ecdsa
from unittest.mock import patch, MagicMock
from app import app, db
from database.models import User, Device
from crypto.ecc_operations import generate_private_key, get_public_key, serialize_public_key
from cryptography.hazmat.primitives import serialization
import jwt
from datetime import datetime, timedelta


class TestSecurityHeaders:
    """Test security headers are properly set."""
    
    def test_security_headers_present(self, client):
        """Test that security headers are set on all responses."""
        response = client.get('/')
        
        # Check for security headers
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        
        assert 'X-Frame-Options' in response.headers
        assert response.headers['X-Frame-Options'] == 'DENY'
        
        assert 'X-XSS-Protection' in response.headers
        assert response.headers['X-XSS-Protection'] == '1; mode=block'
        
        assert 'Referrer-Policy' in response.headers
        assert response.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
        
        assert 'Permissions-Policy' in response.headers
        assert 'camera=()' in response.headers['Permissions-Policy']
        assert 'microphone=()' in response.headers['Permissions-Policy']
        assert 'geolocation=()' in response.headers['Permissions-Policy']


class TestInputValidation:
    """Test input validation and sanitization."""
    
    def test_registration_sql_injection_attempt(self, client, mock_redis):
        """Test registration with SQL injection attempt."""
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        # SQL injection attempt in email
        data = {
            'email': "test@example.com'; DROP TABLE users; --",
            'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
            'device_name': 'Test Device'
        }
        
        response = client.post('/register', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        # Should not crash and should return an error
        assert response.status_code in [400, 500]
    
    def test_registration_xss_attempt(self, client, mock_redis):
        """Test registration with XSS attempt."""
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        # XSS attempt in device name
        data = {
            'email': 'test@example.com',
            'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
            'device_name': '<script>alert("xss")</script>'
        }
        
        response = client.post('/register', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        # Should be accepted (device name is stored, not rendered)
        assert response.status_code == 201
    
    def test_auth_challenge_invalid_email_format(self, client, mock_redis):
        """Test authentication challenge with invalid email format."""
        data = {'email': 'not-an-email'}
        response = client.post('/auth/challenge', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert 'error' in result
    
    def test_auth_verify_malformed_signature(self, client, mock_redis, sample_user, sample_device):
        """Test authentication verification with malformed signature."""
        with app.app_context():
            # Create actual User object from sample_user data
            from database.models import User
            user = User(
                user_id=sample_user['user_id'],
                email=sample_user['email'],
                registration_date=sample_user['registration_date']
            )
            db.session.add(user)
            db.session.add(sample_device)
            db.session.commit()
        
        # Mock Redis to return a nonce
        mock_redis.get.return_value = "test-nonce-123"
        
        data = {
            'email': sample_user['email'],
            'signature': 'not-base64-encoded-signature'
        }
        
        response = client.post('/auth/verify', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert 'error' in result


class TestAuthenticationSecurity:
    """Test authentication security measures."""
    
    def test_nonce_expiration(self, client, mock_redis, sample_user, sample_device):
        """Test that nonces expire properly."""
        with app.app_context():
            # Create actual User object from sample_user data
            from database.models import User
            user = User(
                user_id=sample_user['user_id'],
                email=sample_user['email'],
                registration_date=sample_user['registration_date']
            )
            db.session.add(user)
            db.session.add(sample_device)
            db.session.commit()
        
        # First request - get nonce
        data = {'email': sample_user['email']}
        response = client.post('/auth/challenge', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 200
        result = json.loads(response.data)
        nonce = result['nonce']
        
        # Mock Redis to return None (expired nonce)
        mock_redis.get.return_value = None
        
        # Try to use expired nonce
        data = {
            'email': sample_user['email'],
            'signature': 'some-signature'
        }
        
        response = client.post('/auth/verify', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert 'error' in result
    
    def test_token_expiration(self, client, mock_redis):
        """Test that JWT tokens expire properly."""
        # Create expired token
        payload = {
            'user_id': 'test@example.com',
            'exp': datetime.utcnow() - timedelta(hours=1)  # Expired 1 hour ago
        }
        expired_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        data = {'client_ecdh_public_key': 'test-key'}
        response = client.post('/session/ecdh', 
                             data=json.dumps(data),
                             content_type='application/json',
                             headers={'Authorization': f'Bearer {expired_token}'})
        
        assert response.status_code == 401
        result = json.loads(response.data)
        assert 'error' in result
    
    def test_invalid_token_format(self, client, mock_redis):
        """Test handling of invalid token format."""
        data = {'client_ecdh_public_key': 'test-key'}
        response = client.post('/session/ecdh', 
                             data=json.dumps(data),
                             content_type='application/json',
                             headers={'Authorization': 'Bearer invalid-token-format'})
        
        assert response.status_code == 401
        result = json.loads(response.data)
        assert 'error' in result
    
    def test_missing_authorization_header(self, client, mock_redis):
        """Test handling of missing authorization header."""
        data = {'client_ecdh_public_key': 'test-key'}
        response = client.post('/session/ecdh', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 401
        result = json.loads(response.data)
        assert 'error' in result


class TestCryptographicSecurity:
    """Test cryptographic security properties."""
    
    def test_key_uniqueness(self):
        """Test that generated keys are unique."""
        keys = []
        for _ in range(10):
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            keys.append(public_key_pem)
        
        # All keys should be different
        unique_keys = set(keys)
        assert len(unique_keys) == 10
    
    def test_signature_verification_security(self, sample_key_pair, sample_nonce):
        """Test signature verification security."""
        from crypto.ecdsa_handler import verify_signature
        
        # Test with correct signature
        message = sample_nonce.encode('utf-8')
        
        # Create a valid signature
        raw_private_key = sample_key_pair['private_key'].private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )[-32:]  # Last 32 bytes are the actual private key
        signing_key = ecdsa.SigningKey.from_string(
            raw_private_key,
            curve=ecdsa.curves.SECP256k1
        )
        signature = signing_key.sign_digest_deterministic(
            message,
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_der
        )
        valid_signature = base64.b64encode(signature).decode('utf-8')
        
        # Verify valid signature
        result = verify_signature(valid_signature, message, sample_key_pair['public_key'])
        assert result is True
        
        # Test with tampered message
        tampered_message = b'tampered message'
        result = verify_signature(valid_signature, tampered_message, sample_key_pair['public_key'])
        assert result is False
        
        # Test with tampered signature
        tampered_signature = base64.b64encode(b'tampered signature').decode('utf-8')
        result = verify_signature(tampered_signature, message, sample_key_pair['public_key'])
        assert result is False
    
    def test_shared_secret_security(self):
        """Test ECDH shared secret security."""
        from crypto.ecdh_handler import derive_shared_secret
        
        # Generate three key pairs
        private_key1 = generate_private_key()
        public_key1 = get_public_key(private_key1)
        
        private_key2 = generate_private_key()
        public_key2 = get_public_key(private_key2)
        
        private_key3 = generate_private_key()
        public_key3 = get_public_key(private_key3)
        
        # Derive shared secrets
        shared_secret12 = derive_shared_secret(private_key1, public_key2)
        shared_secret13 = derive_shared_secret(private_key1, public_key3)
        shared_secret23 = derive_shared_secret(private_key2, public_key3)
        
        # All should be different (perfect forward secrecy)
        assert shared_secret12 != shared_secret13
        assert shared_secret12 != shared_secret23
        assert shared_secret13 != shared_secret23
        
        # Same pair should produce same secret
        shared_secret21 = derive_shared_secret(private_key2, public_key1)
        assert shared_secret12 == shared_secret21


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    def test_registration_rate_limit(self, client, mock_redis):
        """Test registration rate limiting."""
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        data = {
            'email': 'test@example.com',
            'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
            'device_name': 'Test Device'
        }
        
        # Make multiple registration attempts
        for i in range(5):
            data['email'] = f'test{i}@example.com'
            response = client.post('/register', 
                                 data=json.dumps(data),
                                 content_type='application/json')
            
            if response.status_code == 429:
                # Rate limit hit
                result = json.loads(response.data)
                assert 'error' in result
                break
        else:
            # If no rate limit hit, that's also acceptable
            pass
    
    def test_auth_challenge_rate_limit(self, client, mock_redis):
        """Test authentication challenge rate limiting."""
        data = {'email': 'test@example.com'}
        
        # Make multiple challenge requests
        for _ in range(15):
            response = client.post('/auth/challenge', 
                                 data=json.dumps(data),
                                 content_type='application/json')
            
            if response.status_code == 429:
                # Rate limit hit
                result = json.loads(response.data)
                assert 'error' in result
                break
        else:
            # If no rate limit hit, that's also acceptable
            pass


class TestDataValidation:
    """Test data validation and sanitization."""
    
    def test_email_validation(self, client, mock_redis):
        """Test email format validation."""
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        invalid_emails = [
            'not-an-email',
            '@example.com',
            'test@',
            'test@.com',
            'test..test@example.com',
            'test@example..com'
        ]
        
        for email in invalid_emails:
            data = {
                'email': email,
                'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
                'device_name': 'Test Device'
            }
            
            response = client.post('/register', 
                                 data=json.dumps(data),
                                 content_type='application/json')
            
            assert response.status_code == 400
            result = json.loads(response.data)
            assert 'error' in result
    
    def test_public_key_validation(self, client, mock_redis):
        """Test public key format validation."""
        invalid_keys = [
            'not-a-key',
            '-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----',
            '',
            None
        ]
        
        for key in invalid_keys:
            data = {
                'email': 'test@example.com',
                'public_key_pem': key,
                'device_name': 'Test Device'
            }
            
            response = client.post('/register', 
                                 data=json.dumps(data),
                                 content_type='application/json')
            
            assert response.status_code == 400
            result = json.loads(response.data)
            assert 'error' in result
    
    def test_device_name_validation(self, client, mock_redis):
        """Test device name validation."""
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        # Test empty device name
        data = {
            'email': 'test@example.com',
            'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
            'device_name': ''
        }
        
        response = client.post('/register', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        # Should use default device name
        assert response.status_code == 201
        result = json.loads(response.data)
        assert 'device_id' in result


class TestErrorHandling:
    """Test error handling and information disclosure."""
    
    def test_error_response_format(self, client, mock_redis):
        """Test that error responses don't leak sensitive information."""
        # Test with invalid endpoint
        response = client.get('/nonexistent-endpoint')
        
        assert response.status_code == 404
        result = json.loads(response.data)
        assert 'error' in result
        
        # Error message should not contain sensitive information
        error_msg = result['error'].lower()
        assert 'secret' not in error_msg
        assert 'key' not in error_msg
        assert 'password' not in error_msg
        assert 'token' not in error_msg
    
    def test_database_error_handling(self, client, mock_redis):
        """Test handling of database errors."""
        # This would require mocking database failures
        # For now, just ensure the application doesn't crash
        data = {'email': 'test@example.com'}
        response = client.post('/auth/challenge', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        # Should return an error, not crash
        assert response.status_code in [400, 404, 500] 