from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    email_verified = db.Column(db.Boolean, default=False)  # Track email verification status
    # Relationship to devices
    devices = db.relationship('Device', backref='user', lazy=True, cascade='all, delete-orphan')

class Device(db.Model):
    __tablename__ = 'devices'
    device_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.user_id'), nullable=False)
    device_name = db.Column(db.String(255), nullable=False, default='Unknown Device')
    public_key = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class AuthLog(db.Model):
    __tablename__ = 'auth_logs'
    log_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.user_id'))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.device_id'))
    event_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    success = db.Column(db.Boolean)

class Session(db.Model):
    __tablename__ = 'sessions'
    session_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.user_id'))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.device_id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True) 