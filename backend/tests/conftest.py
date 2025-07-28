import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
import sys

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app, db
    from database.models import User, Device, Session, AuthLog
    from crypto.ecc_operations import generate_private_key, get_public_key, serialize_public_key
except ImportError as e:
    print(f"Import error: {e}")
    print("Current working directory:", os.getcwd())
    print("Python path:", sys.path)
    raise

import redis
import jwt
from datetime import datetime, timedelta
import ecdsa
import hashlib
import base64
from cryptography.hazmat.primitives import serialization


@pytest.fixture
def test_app():
    """Create a test Flask application."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['REDIS_URL'] = 'redis://localhost:6379/1'  # Use different DB for tests
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(test_app):
    """Create a test client."""
    return test_app.test_client()


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    with patch('app.redis_client') as mock_redis:
        # Mock Redis methods
        mock_redis.get.return_value = None
        mock_redis.setex.return_value = True
        mock_redis.exists.return_value = False
        mock_redis.delete.return_value = True
        yield mock_redis


@pytest.fixture
def sample_user():
    """Create a sample user for testing."""
    # Return a simple dict instead of a database object to avoid session issues
    return {
        'user_id': 'test-user-123',
        'email': 'test@example.com',
        'registration_date': datetime.utcnow()
    }


@pytest.fixture
def sample_device(sample_user):
    """Create a sample device for testing."""
    # Generate a real key pair for testing
    private_key = generate_private_key()
    public_key = get_public_key(private_key)
    public_key_pem = serialize_public_key(public_key)
    
    device = Device(
        device_id='test-device-123',
        user_id=sample_user['user_id'],
        device_name='Test Device',
        public_key=public_key_pem,  # Already bytes, no need to encode
        created_at=datetime.utcnow(),
        last_used=datetime.utcnow(),
        is_active=True
    )
    return device


@pytest.fixture
def auth_token(sample_user):
    """Create a valid JWT token for testing."""
    payload = {
        'user_id': sample_user['email'],
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


@pytest.fixture
def sample_key_pair():
    """Generate a sample ECC key pair for testing."""
    private_key = generate_private_key()
    public_key = get_public_key(private_key)
    public_key_pem = serialize_public_key(public_key)
    
    return {
        'private_key': private_key,
        'public_key': public_key,
        'public_key_pem': public_key_pem
    }


@pytest.fixture
def sample_nonce():
    """Generate a sample nonce for testing."""
    return "test-nonce-123456789"


@pytest.fixture
def sample_signature(sample_key_pair, sample_nonce):
    """Generate a valid signature for testing."""
    # Convert private key to ECDSA format (raw bytes)
    private_key_bytes = sample_key_pair['private_key'].private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Extract the raw private key bytes (32 bytes) from DER
    from cryptography.hazmat.primitives.asymmetric import ec
    # Get the private key as raw bytes
    raw_private_key = sample_key_pair['private_key'].private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )[-32:]  # Last 32 bytes are the actual private key
    # For ECDSA, we need to extract the actual private key value
    # This is a simplified approach - in production you'd use proper key derivation
    signing_key = ecdsa.SigningKey.from_string(
        raw_private_key,  # Use the raw private key directly
        curve=ecdsa.curves.SECP256k1
    )
    
    # Sign the nonce
    signature = signing_key.sign_digest_deterministic(
        sample_nonce.encode('utf-8'),
        hashfunc=hashlib.sha256,
        sigencode=ecdsa.util.sigencode_der
    )
    
    return base64.b64encode(signature).decode('utf-8')


class TestConfig:
    """Test configuration class."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SECRET_KEY = 'test-secret-key'
    REDIS_URL = 'redis://localhost:6379/1' 