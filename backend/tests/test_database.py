import pytest
from datetime import datetime, timedelta
from app import app, db
from database.models import User, Device, Session, AuthLog

@pytest.fixture(autouse=True)
def setup_test_db():
    """Set up a clean test database for each test."""
    with app.app_context():
        db.drop_all()
        db.create_all()
    yield
    with app.app_context():
        db.drop_all()
from database.db_operations import (
    add_user, 
    get_user_by_email, 
    get_user_by_id,
    add_device,
    get_user_devices,
    get_device_by_public_key,
    update_device_last_used,
    remove_device,
    add_session,
    add_auth_log,
    get_user_sessions
)
from crypto.ecc_operations import generate_private_key, get_public_key, serialize_public_key


class TestUserOperations:
    """Test user database operations."""
    

    
    def test_add_user_success(self):
        """Test successful user creation."""
        with app.app_context():
            # Generate test key pair
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            assert user_id is not None
            assert device_id is not None
            
            # Verify user was created
            user = get_user_by_email('test@example.com')
            assert user is not None
            assert user.email == 'test@example.com'
            assert user.user_id == user_id
            
            # Verify device was created
            devices = get_user_devices(user_id)
            assert len(devices) == 1
            assert devices[0].device_id == device_id
            assert devices[0].device_name == 'Test Device'
    
    def test_add_user_duplicate_email(self):
        """Test adding user with duplicate email."""
        with app.app_context():
            # Create first user
            private_key1 = generate_private_key()
            public_key1 = get_public_key(private_key1)
            public_key_pem1 = serialize_public_key(public_key1)
            
            add_user('test@example.com', public_key_pem1, 'Device 1')
            
            # Try to create second user with same email
            private_key2 = generate_private_key()
            public_key2 = get_public_key(private_key2)
            public_key_pem2 = serialize_public_key(public_key2)
            
            with pytest.raises(Exception):  # Should raise an exception
                add_user('test@example.com', public_key_pem2, 'Device 2')
    
    def test_get_user_by_email(self):
        """Test retrieving user by email."""
        with app.app_context():
            # Create user
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, _ = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Retrieve user
            user = get_user_by_email('test@example.com')
            assert user is not None
            assert user.user_id == user_id
            assert user.email == 'test@example.com'
    
    def test_get_user_by_email_not_found(self):
        """Test retrieving non-existent user by email."""
        with app.app_context():
            user = get_user_by_email('nonexistent@example.com')
            assert user is None
    
    def test_get_user_by_id(self):
        """Test retrieving user by ID."""
        with app.app_context():
            # Create user
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, _ = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Retrieve user by ID
            user = get_user_by_id(user_id)
            assert user is not None
            assert user.email == 'test@example.com'
    
    def test_get_user_by_id_not_found(self):
        """Test retrieving non-existent user by ID."""
        with app.app_context():
            user = get_user_by_id('nonexistent-id')
            assert user is None


class TestDeviceOperations:
    """Test device database operations."""
    
    def test_add_device_success(self):
        """Test successful device addition."""
        with app.app_context():
            # Create user first
            private_key1 = generate_private_key()
            public_key1 = get_public_key(private_key1)
            public_key_pem1 = serialize_public_key(public_key1)
            
            user_id, _ = add_user('test@example.com', public_key_pem1, 'Device 1')
            
            # Add second device
            private_key2 = generate_private_key()
            public_key2 = get_public_key(private_key2)
            public_key_pem2 = serialize_public_key(public_key2)
            
            device_id = add_device(user_id, public_key_pem2, 'Device 2')
            
            assert device_id is not None
            
            # Verify device was added
            devices = get_user_devices(user_id)
            assert len(devices) == 2
            
            # Check that both devices exist
            device_names = [d.device_name for d in devices]
            assert 'Device 1' in device_names
            assert 'Device 2' in device_names
    
    def test_get_user_devices(self):
        """Test retrieving user devices."""
        with app.app_context():
            # Create user with device
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, _ = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Add second device
            private_key2 = generate_private_key()
            public_key2 = get_public_key(private_key2)
            public_key_pem2 = serialize_public_key(public_key2)
            
            add_device(user_id, public_key_pem2, 'Device 2')
            
            # Retrieve devices
            devices = get_user_devices(user_id)
            assert len(devices) == 2
            assert all(d.user_id == user_id for d in devices)
    
    def test_get_device_by_public_key(self):
        """Test retrieving device by public key."""
        with app.app_context():
            # Create user with device
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Retrieve device by public key
            device = get_device_by_public_key(public_key_pem)
            assert device is not None
            assert device.device_id == device_id
            assert device.user_id == user_id
    
    def test_get_device_by_public_key_not_found(self):
        """Test retrieving device with non-existent public key."""
        with app.app_context():
            # Generate a different key
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            device = get_device_by_public_key(public_key_pem)
            assert device is None
    
    def test_update_device_last_used(self):
        """Test updating device last used timestamp."""
        with app.app_context():
            # Create user with device
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Get initial last_used
            device = get_device_by_public_key(public_key_pem)
            initial_last_used = device.last_used
            
            # Update last_used
            update_device_last_used(device_id)
            
            # Verify update
            device = get_device_by_public_key(public_key_pem)
            assert device.last_used is not None
            assert device.last_used > initial_last_used
    
    def test_remove_device(self):
        """Test device removal."""
        with app.app_context():
            # Create user with device
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Add second device
            private_key2 = generate_private_key()
            public_key2 = get_public_key(private_key2)
            public_key_pem2 = serialize_public_key(public_key2)
            
            device_id2 = add_device(user_id, public_key_pem2, 'Device 2')
            
            # Remove first device
            remove_device(device_id, user_id)
            
            # Verify device was removed
            devices = get_user_devices(user_id)
            assert len(devices) == 1
            assert devices[0].device_id == device_id2.device_id
            
            # Verify device is not found by public key
            device = get_device_by_public_key(public_key_pem)
            assert device is None


class TestSessionOperations:
    """Test session database operations."""
    
    def test_add_session_success(self):
        """Test successful session creation."""
        with app.app_context():
            # Create user
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Create session
            session_id = 'test-session-123'
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            add_session(session_id, user_id, device_id, expires_at)
            
            # Verify session was created
            session = Session.query.filter_by(session_id=session_id).first()
            assert session is not None
            assert session.user_id == user_id
            assert session.device_id == device_id
            assert session.is_active is True
    
    def test_get_user_sessions(self):
        """Test retrieving user sessions."""
        with app.app_context():
            # Create user
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Create multiple sessions
            session_id1 = 'test-session-1'
            session_id2 = 'test-session-2'
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            add_session(session_id1, user_id, device_id, expires_at)
            add_session(session_id2, user_id, device_id, expires_at)
            
            # Retrieve sessions
            sessions = get_user_sessions(user_id)
            assert len(sessions) == 2
            assert all(s.user_id == user_id for s in sessions)


class TestAuthLogOperations:
    """Test authentication log operations."""
    
    def test_add_auth_log_success(self):
        """Test successful auth log creation."""
        with app.app_context():
            # Create user
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Create auth log
            add_auth_log(
                user_id=user_id,
                device_id=device_id,
                event_type='login_success',
                ip_address='127.0.0.1',
                user_agent='Test Browser',
                success=True
            )
            
            # Verify auth log was created
            auth_log = AuthLog.query.filter_by(user_id=user_id).first()
            assert auth_log is not None
            assert auth_log.event_type == 'login_success'
            assert auth_log.ip_address == '127.0.0.1'
            assert auth_log.success is True


class TestDatabaseConstraints:
    """Test database constraints and relationships."""
    
    def test_user_device_relationship(self):
        """Test user-device relationship."""
        with app.app_context():
            # Create user with device
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Verify relationship
            user = get_user_by_id(user_id)
            devices = get_user_devices(user_id)
            
            assert len(devices) == 1
            assert devices[0].user_id == user_id
            assert devices[0].user == user
    
    def test_device_session_relationship(self):
        """Test device-session relationship."""
        with app.app_context():
            # Create user with device
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Create session
            session_id = 'test-session-123'
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            add_session(session_id, user_id, device_id, expires_at)
            
            # Verify relationship
            session = Session.query.filter_by(session_id=session_id).first()
            device = get_device_by_public_key(public_key_pem)
            
            assert session.device_id == device_id
            assert session.device == device
    
    def test_cascade_delete(self):
        """Test cascade delete behavior."""
        with app.app_context():
            # Create user with device
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            
            user_id, device_id = add_user('test@example.com', public_key_pem, 'Test Device')
            
            # Create session and auth log
            session_id = 'test-session-123'
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            add_session(session_id, user_id, device_id, expires_at)
            add_auth_log(user_id, device_id, 'login_success', '127.0.0.1', 'Test Browser', True)
            
            # Delete user (should cascade to devices, sessions, and auth logs)
            user = get_user_by_id(user_id)
            db.session.delete(user)
            db.session.commit()
            
            # Verify everything was deleted
            assert get_user_by_id(user_id) is None
            assert get_user_devices(user_id) == []
            assert Session.query.filter_by(user_id=user_id).first() is None
            assert AuthLog.query.filter_by(user_id=user_id).first() is None 