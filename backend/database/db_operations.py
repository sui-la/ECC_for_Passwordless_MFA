from .models import db, User, Device, Session, AuthLog
from datetime import datetime

def add_user(email, public_key, device_name="Unknown Device"):
    """Create a new user with their first device."""
    user = User(email=email, email_verified=False)  # Set email_verified to False by default
    db.session.add(user)
    db.session.flush()  # Get the user_id
    
    # Create the first device for this user
    device = Device(
        user_id=user.user_id,
        device_name=device_name,
        public_key=public_key
    )
    db.session.add(device)
    db.session.commit()
    return user.user_id, device.device_id

def get_user_by_email(email):
    return User.query.filter_by(email=email).first()

def get_user_by_id(user_id):
    return User.query.get(user_id)

def add_device(user_id, public_key, device_name="Unknown Device"):
    """Add a new device for an existing user."""
    device = Device(
        user_id=user_id,
        device_name=device_name,
        public_key=public_key
    )
    db.session.add(device)
    db.session.commit()
    return device

def get_user_devices(user_id):
    """Get all active devices for a user."""
    return Device.query.filter_by(user_id=user_id, is_active=True).all()

def get_device_by_public_key(public_key):
    """Find a device by its public key."""
    return Device.query.filter_by(public_key=public_key, is_active=True).first()

def update_device_last_used(device_id):
    """Update the last_used timestamp for a device."""
    device = Device.query.get(device_id)
    if device:
        device.last_used = datetime.utcnow()
        db.session.commit()

def remove_device(device_id, user_id):
    """Deactivate a device (soft delete)."""
    device = Device.query.filter_by(device_id=device_id, user_id=user_id).first()
    if device:
        device.is_active = False
        db.session.commit()
        return True
    return False

def add_session(session_id, user_id, device_id, expires_at):
    session = Session(
        session_id=session_id,
        user_id=user_id,
        device_id=device_id,
        expires_at=expires_at
    )
    db.session.add(session)
    db.session.commit()
    return session

def get_session_by_id(session_id):
    return Session.query.filter_by(session_id=session_id, is_active=True).first()

def get_user_sessions(user_id):
    """Get all active sessions for a user."""
    return Session.query.filter_by(user_id=user_id, is_active=True).all()

def add_auth_log(user_id, device_id, event_type, ip_address, user_agent, success):
    """Add an authentication log entry."""
    log = AuthLog(
        user_id=user_id,
        device_id=device_id,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success
    )
    db.session.add(log)
    db.session.commit()
    return log

def mark_user_email_verified(user_id):
    """Mark a user's email as verified."""
    user = User.query.get(user_id)
    if user:
        user.email_verified = True
        db.session.commit()
        return True
    return False

# Database management functions
def clear_all_data():
    """Delete all data from all tables while keeping the table structure."""
    try:
        # Delete all records from all tables
        Session.query.delete()
        AuthLog.query.delete()
        Device.query.delete()
        User.query.delete()
        
        # Commit the changes
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        raise e

def reset_database():
    """Drop all tables and recreate them (complete reset)."""
    try:
        # Drop all tables
        db.drop_all()
        # Create all tables
        db.create_all()
        return True
    except Exception as e:
        raise e

def get_database_stats():
    """Get statistics about the database."""
    return {
        'users': User.query.count(),
        'devices': Device.query.count(),
        'sessions': Session.query.count(),
        'auth_logs': AuthLog.query.count()
    } 