"""
Blueprints package for ECC Passwordless MFA.
Organizes routes by functionality for better maintainability.
"""

from .auth import auth_bp
from .devices import devices_bp
from .sessions import sessions_bp
from .recovery import recovery_bp
from .monitoring import monitoring_bp
from .admin import admin_bp

__all__ = [
    'auth_bp',
    'devices_bp', 
    'sessions_bp',
    'recovery_bp',
    'monitoring_bp',
    'admin_bp'
]
