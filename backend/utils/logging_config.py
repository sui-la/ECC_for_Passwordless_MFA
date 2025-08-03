"""
Comprehensive logging configuration for ECC Passwordless MFA.
Provides structured logging, different levels, and log rotation.
"""

import logging
import logging.handlers
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logging."""
    
    def format(self, record):
        """Format log record as structured JSON."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        # Add request context if available
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        if hasattr(record, 'ip_address'):
            log_entry['ip_address'] = record.ip_address
        
        return json.dumps(log_entry, ensure_ascii=False)

class SecurityFormatter(logging.Formatter):
    """Custom formatter for security-related logs."""
    
    def format(self, record):
        """Format security log record."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'category': 'security',
            'event': getattr(record, 'security_event', 'unknown'),
            'message': record.getMessage(),
            'ip_address': getattr(record, 'ip_address', 'unknown'),
            'user_agent': getattr(record, 'user_agent', 'unknown'),
            'user_id': getattr(record, 'user_id', 'unknown'),
            'session_id': getattr(record, 'session_id', 'unknown')
        }
        
        # Add security-specific fields
        if hasattr(record, 'auth_type'):
            log_entry['auth_type'] = record.auth_type
        if hasattr(record, 'success'):
            log_entry['success'] = record.success
        if hasattr(record, 'failure_reason'):
            log_entry['failure_reason'] = record.failure_reason
        
        return json.dumps(log_entry, ensure_ascii=False)

class AuditFormatter(logging.Formatter):
    """Custom formatter for audit logs."""
    
    def format(self, record):
        """Format audit log record."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'category': 'audit',
            'action': getattr(record, 'audit_action', 'unknown'),
            'resource': getattr(record, 'audit_resource', 'unknown'),
            'user_id': getattr(record, 'user_id', 'unknown'),
            'ip_address': getattr(record, 'ip_address', 'unknown'),
            'details': record.getMessage()
        }
        
        return json.dumps(log_entry, ensure_ascii=False)

class LoggingConfig:
    """Centralized logging configuration."""
    
    def __init__(self, app_name: str = 'ecc_mfa', log_dir: str = 'logs'):
        self.app_name = app_name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Environment-based configuration
        self.environment = os.environ.get('FLASK_ENV', 'development')
        self.is_production = self.environment == 'production'
        
        # Log levels
        self.console_level = logging.INFO if self.is_production else logging.DEBUG
        self.file_level = logging.DEBUG
        self.security_level = logging.WARNING
        
        # Log file paths
        self.app_log_file = self.log_dir / f'{app_name}.log'
        self.error_log_file = self.log_dir / f'{app_name}_errors.log'
        self.security_log_file = self.log_dir / f'{app_name}_security.log'
        self.audit_log_file = self.log_dir / f'{app_name}_audit.log'
        self.access_log_file = self.log_dir / f'{app_name}_access.log'
    
    def setup_logging(self):
        """Setup comprehensive logging configuration."""
        
        # Clear existing handlers
        logging.getLogger().handlers.clear()
        
        # Set root logger level
        logging.getLogger().setLevel(logging.DEBUG)
        
        # Create formatters
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_formatter = StructuredFormatter()
        security_formatter = SecurityFormatter()
        audit_formatter = AuditFormatter()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.console_level)
        console_handler.setFormatter(console_formatter)
        
        # Main application log handler
        app_handler = self._create_rotating_handler(
            self.app_log_file, 
            file_formatter, 
            self.file_level,
            max_bytes=10*1024*1024,  # 10MB
            backup_count=5
        )
        
        # Error log handler
        error_handler = self._create_rotating_handler(
            self.error_log_file,
            file_formatter,
            logging.ERROR,
            max_bytes=5*1024*1024,  # 5MB
            backup_count=3
        )
        
        # Security log handler
        security_handler = self._create_rotating_handler(
            self.security_log_file,
            security_formatter,
            self.security_level,
            max_bytes=5*1024*1024,  # 5MB
            backup_count=10
        )
        
        # Audit log handler
        audit_handler = self._create_rotating_handler(
            self.audit_log_file,
            audit_formatter,
            logging.INFO,
            max_bytes=5*1024*1024,  # 5MB
            backup_count=10
        )
        
        # Access log handler
        access_handler = self._create_rotating_handler(
            self.access_log_file,
            file_formatter,
            logging.INFO,
            max_bytes=10*1024*1024,  # 10MB
            backup_count=5
        )
        
        # Setup root logger
        root_logger = logging.getLogger()
        root_logger.addHandler(console_handler)
        root_logger.addHandler(app_handler)
        root_logger.addHandler(error_handler)
        
        # Setup specialized loggers
        self._setup_security_logger(security_handler)
        self._setup_audit_logger(audit_handler)
        self._setup_access_logger(access_handler)
        
        # Suppress noisy loggers
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        
        # Log startup message
        logging.info(f"Logging system initialized for {self.app_name} in {self.environment} mode")
    
    def _create_rotating_handler(self, log_file: Path, formatter: logging.Formatter, 
                                level: int, max_bytes: int = 10*1024*1024, 
                                backup_count: int = 5) -> logging.handlers.RotatingFileHandler:
        """Create a rotating file handler."""
        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        handler.setLevel(level)
        handler.setFormatter(formatter)
        return handler
    
    def _setup_security_logger(self, handler: logging.handlers.RotatingFileHandler):
        """Setup security logger."""
        security_logger = logging.getLogger('security')
        security_logger.setLevel(self.security_level)
        security_logger.addHandler(handler)
        security_logger.propagate = False
    
    def _setup_audit_logger(self, handler: logging.handlers.RotatingFileHandler):
        """Setup audit logger."""
        audit_logger = logging.getLogger('audit')
        audit_logger.setLevel(logging.INFO)
        audit_logger.addHandler(handler)
        audit_logger.propagate = False
    
    def _setup_access_logger(self, handler: logging.handlers.RotatingFileHandler):
        """Setup access logger."""
        access_logger = logging.getLogger('access')
        access_logger.setLevel(logging.INFO)
        access_logger.addHandler(handler)
        access_logger.propagate = False

def log_security_event(event_type: str, message: str, **kwargs):
    """Log a security event."""
    logger = logging.getLogger('security')
    
    # Create log record with security context
    record = logger.makeRecord(
        'security', logging.WARNING, '', 0, message, (), None
    )
    
    # Add security-specific attributes
    for key, value in kwargs.items():
        setattr(record, key, value)
    
    record.security_event = event_type
    logger.handle(record)

def log_audit_event(action: str, resource: str, message: str, **kwargs):
    """Log an audit event."""
    logger = logging.getLogger('audit')
    
    # Create log record with audit context
    record = logger.makeRecord(
        'audit', logging.INFO, '', 0, message, (), None
    )
    
    # Add audit-specific attributes
    for key, value in kwargs.items():
        setattr(record, key, value)
    
    record.audit_action = action
    record.audit_resource = resource
    logger.handle(record)

def log_access_event(method: str, path: str, status_code: int, response_time: float, **kwargs):
    """Log an access event."""
    logger = logging.getLogger('access')
    
    message = f"{method} {path} {status_code} {response_time:.3f}s"
    
    # Create log record with access context
    record = logger.makeRecord(
        'access', logging.INFO, '', 0, message, (), None
    )
    
    # Add access-specific attributes
    for key, value in kwargs.items():
        setattr(record, key, value)
    
    record.method = method
    record.path = path
    record.status_code = status_code
    record.response_time = response_time
    logger.handle(record)

def log_request_context(request_id: str, user_id: Optional[str] = None, 
                       ip_address: Optional[str] = None, **kwargs):
    """Add request context to log records."""
    logger = logging.getLogger()
    
    # Create a filter to add request context
    class RequestContextFilter(logging.Filter):
        def filter(self, record):
            record.request_id = request_id
            if user_id:
                record.user_id = user_id
            if ip_address:
                record.ip_address = ip_address
            for key, value in kwargs.items():
                setattr(record, key, value)
            return True
    
    # Add filter to all handlers
    for handler in logger.handlers:
        handler.addFilter(RequestContextFilter())

def get_log_stats() -> Dict[str, Any]:
    """Get logging statistics."""
    log_dir = Path('logs')
    if not log_dir.exists():
        return {'error': 'Log directory not found'}
    
    stats = {
        'log_directory': str(log_dir.absolute()),
        'files': {},
        'total_size': 0
    }
    
    for log_file in log_dir.glob('*.log*'):
        try:
            size = log_file.stat().st_size
            stats['files'][log_file.name] = {
                'size_bytes': size,
                'size_mb': round(size / (1024 * 1024), 2),
                'modified': datetime.fromtimestamp(log_file.stat().st_mtime).isoformat()
            }
            stats['total_size'] += size
        except Exception as e:
            stats['files'][log_file.name] = {'error': str(e)}
    
    stats['total_size_mb'] = round(stats['total_size'] / (1024 * 1024), 2)
    return stats

def cleanup_old_logs(max_age_days: int = 30):
    """Clean up old log files."""
    log_dir = Path('logs')
    if not log_dir.exists():
        return
    
    cutoff_time = datetime.now().timestamp() - (max_age_days * 24 * 60 * 60)
    cleaned_files = []
    
    for log_file in log_dir.glob('*.log*'):
        try:
            if log_file.stat().st_mtime < cutoff_time:
                log_file.unlink()
                cleaned_files.append(log_file.name)
        except Exception as e:
            logging.warning(f"Failed to clean up {log_file}: {e}")
    
    if cleaned_files:
        logging.info(f"Cleaned up {len(cleaned_files)} old log files: {cleaned_files}")
    
    return cleaned_files 