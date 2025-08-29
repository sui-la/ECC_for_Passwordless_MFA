import os
from typing import Optional

class Config:
    """Base configuration class with environment-based settings."""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    DEBUG = os.environ.get('FLASK_ENV') == 'development'
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://hao:suisui0322@db:5432/eccmfa')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Redis Configuration
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('SMTP_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('EMAIL_USER', 'eccmfa@gmail.com')
    MAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('EMAIL_USER', 'eccmfa@gmail.com')
    
    # Security Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', '300'))
    
    # Rate Limiting Configuration
    RATE_LIMIT_STORAGE_URL = REDIS_URL
    RATE_LIMIT_STRATEGY = os.environ.get('RATE_LIMIT_STRATEGY', 'fixed-window')
    
    # Session Configuration
    SESSION_DURATION_MINUTES = int(os.environ.get('SESSION_DURATION_MINUTES', '5'))
    
    # API Configuration
    API_VERSION = os.environ.get('API_VERSION', 'v1')
    API_TITLE = os.environ.get('API_TITLE', 'ECC Passwordless MFA API')
    
    @classmethod
    def validate_config(cls) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        # Check required environment variables
        if not cls.MAIL_PASSWORD and cls.FLASK_ENV == 'production':
            issues.append("EMAIL_PASSWORD environment variable is required for email functionality in production")
        
        if not cls.SECRET_KEY or cls.SECRET_KEY == 'supersecretkey':
            issues.append("SECRET_KEY should be set to a secure random value")
        
        # Check database URL format
        if not cls.SQLALCHEMY_DATABASE_URI.startswith(('postgresql://', 'postgres://')):
            issues.append("DATABASE_URL should be a valid PostgreSQL connection string")
        
        # Check Redis URL format
        if not cls.REDIS_URL.startswith('redis://'):
            issues.append("REDIS_URL should be a valid Redis connection string")
        
        return issues

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    FLASK_ENV = 'development'

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    FLASK_ENV = 'production'
    
    # Production-specific settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    @classmethod
    def validate_config(cls) -> list[str]:
        """Additional validation for production."""
        issues = super().validate_config()
        
        # Production-specific checks
        if cls.SECRET_KEY == 'supersecretkey':
            issues.append("SECRET_KEY must be set in production")
        
        if not cls.MAIL_PASSWORD:
            issues.append("EMAIL_PASSWORD must be set in production")
        
        return issues

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    REDIS_URL = 'redis://localhost:6379/1'  # Use different database for testing

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}