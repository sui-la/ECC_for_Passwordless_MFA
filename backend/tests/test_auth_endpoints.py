import pytest
import json
import base64
from unittest.mock import patch, MagicMock
from app import app, db
from database.models import User, Device
from database.db_operations import add_user, add_device
from crypto.ecc_operations import generate_private_key, get_public_key, serialize_public_key
import jwt
from datetime import datetime, timedelta


class TestRegistration:
    """Test user registration endpoint."""
    
    def test_successful_registration(self, client, mock_redis):
        """Test successful user registration."""
        # Generate test key pair
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        data = {
            'email': 'test@example.com',
            'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
            'device_name': 'Test Device'
        }
        
        response = client.post('/register', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 201
        result = json.loads(response.data)
        assert 'message' in result
        assert 'user_id' in result
        assert 'device_id' in result
    
    def test_registration_duplicate_email(self, client, mock_redis, sample_user, sample_device):
        """Test registration with duplicate email."""
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
        
        # Generate test key pair
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        data = {
            'email': sample_user['email'],
            'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
            'device_name': 'Another Device'
        }
        
        response = client.post('/register', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert 'error' in result
    
    def test_registration_invalid_email(self, client, mock_redis):
        """Test registration with invalid email."""
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        data = {
            'email': 'invalid-email',
            'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
            'device_name': 'Test Device'
        }
        
        response = client.post('/register', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert 'error' in result
    
    def test_registration_invalid_public_key(self, client, mock_redis):
        """Test registration with invalid public key."""
        data = {
            'email': 'test@example.com',
            'public_key_pem': 'invalid-key',
            'device_name': 'Test Device'
        }
        
        response = client.post('/register', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert 'error' in result


class TestAuthentication:
    """Test authentication endpoints."""
    
    def test_auth_challenge_success(self, client, mock_redis, sample_user, sample_device):
        """Test successful authentication challenge."""
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
        
        data = {'email': sample_user['email']}
        response = client.post('/auth/challenge', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 200
        result = json.loads(response.data)
        assert 'nonce' in result
    
    def test_auth_challenge_user_not_found(self, client, mock_redis):
        """Test authentication challenge for non-existent user."""
        data = {'email': 'nonexistent@example.com'}
        response = client.post('/auth/challenge', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 404
        result = json.loads(response.data)
        assert 'error' in result
    
    def test_auth_verify_success(self, client, mock_redis, sample_user, sample_device, sample_nonce, sample_signature):
        """Test successful authentication verification."""
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
        
        # Mock Redis to return the nonce
        mock_redis.get.return_value = sample_nonce
        
        data = {
            'email': sample_user['email'],
            'signature': sample_signature
        }
        
        response = client.post('/auth/verify', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 200
        result = json.loads(response.data)
        assert 'token' in result
        assert 'server_ecdh_public_key' in result
    
    def test_auth_verify_invalid_signature(self, client, mock_redis, sample_user, sample_device, sample_nonce):
        """Test authentication verification with invalid signature."""
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
        
        # Mock Redis to return the nonce
        mock_redis.get.return_value = sample_nonce
        
        data = {
            'email': sample_user['email'],
            'signature': 'invalid-signature'
        }
        
        response = client.post('/auth/verify', 
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 401
        result = json.loads(response.data)
        assert 'error' in result
    
    def test_auth_verify_expired_nonce(self, client, mock_redis, sample_user, sample_device):
        """Test authentication verification with expired nonce."""
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
        
        # Mock Redis to return None (expired nonce)
        mock_redis.get.return_value = None
        
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


class TestSessionManagement:
    """Test session management endpoints."""
    
    def test_ecdh_key_exchange_success(self, client, mock_redis, auth_token, sample_key_pair):
        """Test successful ECDH key exchange."""
        # Mock JWT decode
        with patch('app.jwt.decode') as mock_jwt_decode:
            mock_jwt_decode.return_value = {'user_id': 'test@example.com'}
            
            data = {
                'client_ecdh_public_key': base64.b64encode(sample_key_pair['public_key_pem']).decode('utf-8')
            }
            
            response = client.post('/session/ecdh', 
                                 data=json.dumps(data),
                                 content_type='application/json',
                                 headers={'Authorization': f'Bearer {auth_token}'})
            
            assert response.status_code == 200
            result = json.loads(response.data)
            assert 'message' in result
    
    def test_ecdh_key_exchange_invalid_token(self, client, mock_redis, sample_key_pair):
        """Test ECDH key exchange with invalid token."""
        data = {
            'client_ecdh_public_key': base64.b64encode(sample_key_pair['public_key_pem']).decode('utf-8')
        }
        
        response = client.post('/session/ecdh', 
                             data=json.dumps(data),
                             content_type='application/json',
                             headers={'Authorization': 'Bearer invalid-token'})
        
        assert response.status_code == 401
        result = json.loads(response.data)
        assert 'error' in result
    
    def test_secure_data_exchange_success(self, client, mock_redis, auth_token):
        """Test successful secure data exchange."""
        # Mock JWT decode and Redis
        with patch('app.jwt.decode') as mock_jwt_decode:
            mock_jwt_decode.return_value = {'user_id': 'test@example.com'}
            mock_redis.get.return_value = base64.b64encode(b'test-shared-secret').decode('utf-8')
            
            # Mock AES decryption/encryption
            with patch('app.aes_gcm_decrypt') as mock_decrypt:
                with patch('app.aes_gcm_encrypt') as mock_encrypt:
                    mock_decrypt.return_value = b'decrypted-data'
                    mock_encrypt.return_value = (b'encrypted-data', b'tag')
                    
                    data = {
                        'ciphertext': base64.b64encode(b'test-ciphertext').decode('utf-8'),
                        'iv': base64.b64encode(b'test-iv').decode('utf-8')
                    }
                    
                    response = client.post('/session/secure-data', 
                                         data=json.dumps(data),
                                         content_type='application/json',
                                         headers={'Authorization': f'Bearer {auth_token}'})
                    
                    assert response.status_code == 200
                    result = json.loads(response.data)
                    assert 'ciphertext' in result
                    assert 'iv' in result


class TestDeviceManagement:
    """Test device management endpoints."""
    
    def test_get_devices_success(self, client, mock_redis, auth_token, sample_user, sample_device):
        """Test successful device listing."""
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
        
        with patch('app.jwt.decode') as mock_jwt_decode:
            mock_jwt_decode.return_value = {'user_id': sample_user['email']}
            
            response = client.get('/devices',
                                headers={'Authorization': f'Bearer {auth_token}'})
            
            assert response.status_code == 200
            result = json.loads(response.data)
            assert 'devices' in result
            assert len(result['devices']) == 1
    
    def test_add_device_success(self, client, mock_redis, auth_token, sample_user):
        """Test successful device addition."""
        with app.app_context():
            # Create actual User object from sample_user data
            from database.models import User
            user = User(
                user_id=sample_user['user_id'],
                email=sample_user['email'],
                registration_date=sample_user['registration_date']
            )
            db.session.add(user)
            db.session.commit()
        
        # Generate new key pair for the device
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        with patch('app.jwt.decode') as mock_jwt_decode:
            mock_jwt_decode.return_value = {'user_id': sample_user['email']}
            
            data = {
                'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
                'device_name': 'New Device'
            }
            
            response = client.post('/devices',
                                 data=json.dumps(data),
                                 content_type='application/json',
                                 headers={'Authorization': f'Bearer {auth_token}'})
            
            assert response.status_code == 201
            result = json.loads(response.data)
            assert 'message' in result
            assert 'device_id' in result
    
    def test_remove_device_success(self, client, mock_redis, auth_token, sample_user, sample_device):
        """Test successful device removal."""
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
        
        with patch('app.jwt.decode') as mock_jwt_decode:
            mock_jwt_decode.return_value = {'user_id': sample_user['email']}
            
            response = client.delete(f'/devices/{sample_device.device_id}',
                                   headers={'Authorization': f'Bearer {auth_token}'})
            
            assert response.status_code == 200
            result = json.loads(response.data)
            assert 'message' in result


class TestRecoveryEndpoints:
    """Test recovery endpoints."""
    
    def test_initiate_recovery_success(self, client, mock_redis, sample_user):
        """Test successful recovery initiation."""
        with app.app_context():
            # Create actual User object from sample_user data
            from database.models import User
            user = User(
                user_id=sample_user['user_id'],
                email=sample_user['email'],
                registration_date=sample_user['registration_date']
            )
            db.session.add(user)
            db.session.commit()
        
        # Mock email sending
        with patch('app.send_notification_email') as mock_email:
            mock_email.return_value = True
            
            data = {'email': sample_user['email']}
            response = client.post('/recovery/initiate',
                                 data=json.dumps(data),
                                 content_type='application/json')
            
            assert response.status_code == 200
            result = json.loads(response.data)
            assert 'message' in result
    
    def test_verify_recovery_token_success(self, client, mock_redis, sample_user):
        """Test successful recovery token verification."""
        # Mock Redis to return user ID
        mock_redis.get.return_value = sample_user['user_id']
        
        data = {'recovery_token': 'test-token'}
        response = client.post('/recovery/verify-token',
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 200
        result = json.loads(response.data)
        assert 'email' in result
    
    def test_complete_recovery_success(self, client, mock_redis, sample_user):
        """Test successful recovery completion."""
        # Mock Redis to return user ID
        mock_redis.get.return_value = sample_user['user_id']
        
        # Generate new key pair
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        data = {
            'recovery_token': 'test-token',
            'public_key_pem': base64.b64encode(public_key_pem).decode('utf-8'),
            'device_name': 'Recovery Device'
        }
        
        response = client.post('/recovery/complete',
                             data=json.dumps(data),
                             content_type='application/json')
        
        assert response.status_code == 200
        result = json.loads(response.data)
        assert 'message' in result
        assert 'device_id' in result 