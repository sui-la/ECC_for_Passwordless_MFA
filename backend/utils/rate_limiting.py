from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import request, jsonify
import logging
from typing import Dict, Any, Optional
import redis
import time

logger = logging.getLogger(__name__)

class RateLimitConfig:
    """Configuration for rate limiting strategies."""
    
    # Authentication endpoints
    AUTH_CHALLENGE_LIMIT = "5 per minute"
    AUTH_VERIFY_LIMIT = "10 per minute"
    REGISTRATION_LIMIT = "3 per hour"
    
    # Recovery endpoints
    RECOVERY_INITIATE_LIMIT = "2 per hour"
    RECOVERY_VERIFY_LIMIT = "5 per hour"
    RECOVERY_COMPLETE_LIMIT = "3 per hour"
    
    # Device management
    DEVICE_ADD_LIMIT = "5 per hour"
    DEVICE_REMOVE_LIMIT = "10 per hour"
    DEVICE_LIST_LIMIT = "30 per minute"
    
    # General API endpoints
    GENERAL_API_LIMIT = "100 per minute"
    PROFILE_LIMIT = "30 per minute"
    
    # Session management
    SESSION_ECDH_LIMIT = "20 per minute"
    SESSION_SECURE_DATA_LIMIT = "100 per minute"
    


def get_client_identifier():
    """
    Get a unique identifier for the client for rate limiting.
    Uses X-Forwarded-For header if available (for proxy setups).
    """
    # Check for X-Forwarded-For header (common with proxies)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Take the first IP in the chain
        client_ip = forwarded_for.split(',')[0].strip()
    else:
        client_ip = get_remote_address()
    
    # Add user agent as additional identifier for better rate limiting
    user_agent = request.headers.get('User-Agent', 'unknown')
    
    # Create a composite identifier
    identifier = f"{client_ip}:{hash(user_agent) % 1000}"
    
    return identifier

def create_rate_limiter(app, redis_client: redis.Redis):
    """
    Create and configure rate limiter with Redis backend.
    
    Args:
        app: Flask application
        redis_client: Redis client for storage
        
    Returns:
        Limiter: Configured rate limiter
    """
    # Get Redis connection details
    try:
        host = redis_client.connection_pool.connection_kwargs['host']
        port = redis_client.connection_pool.connection_kwargs['port']
        storage_uri = f"redis://{host}:{port}"
    except (KeyError, AttributeError):
        # Fallback to default Redis connection
        storage_uri = "redis://localhost:6379"
    
    limiter = Limiter(
        app=app,
        key_func=get_client_identifier,
        storage_uri=storage_uri,
        default_limits=[RateLimitConfig.GENERAL_API_LIMIT],
        strategy="fixed-window"  # Use valid strategy
    )
    
    return limiter

def rate_limit_exceeded_handler(e):
    """
    Custom handler for rate limit exceeded errors.
    
    Args:
        e: Rate limit exceeded exception
        
    Returns:
        JSON response with error details
    """
    logger.warning(f"Rate limit exceeded for {get_client_identifier()}: {str(e)}")
    
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'retry_after': getattr(e, 'retry_after', 60),
        'limit': getattr(e, 'limit', 'unknown')
    }), 429

def get_rate_limit_headers(response, limit, remaining, reset):
    """
    Add rate limit headers to response.
    
    Args:
        response: Flask response object
        limit: Rate limit value
        remaining: Remaining requests
        reset: Reset time
        
    Returns:
        Response: Response with rate limit headers
    """
    response.headers['X-RateLimit-Limit'] = str(limit)
    response.headers['X-RateLimit-Remaining'] = str(remaining)
    response.headers['X-RateLimit-Reset'] = str(reset)
    response.headers['X-RateLimit-Reset-Time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(reset))
    
    return response

def check_rate_limit_health(redis_client: redis.Redis) -> Dict[str, Any]:
    """
    Check the health of rate limiting system.
    
    Args:
        redis_client: Redis client
        
    Returns:
        Dict: Health status information
    """
    try:
        # Test Redis connection
        redis_client.ping()
        redis_status = "healthy"
    except Exception as e:
        logger.error(f"Rate limiting Redis health check failed: {e}")
        redis_status = "unhealthy"
    
    return {
        "rate_limiting": {
            "status": redis_status,
            "backend": "redis",
            "timestamp": time.time()
        }
    }

# Rate limiting decorators for specific endpoints
def auth_rate_limit():
    """Rate limiting decorator for authentication endpoints."""
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def registration_rate_limit():
    """Rate limiting decorator for registration endpoint."""
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def recovery_rate_limit():
    """Rate limiting decorator for recovery endpoints."""
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def device_management_rate_limit():
    """Rate limiting decorator for device management endpoints."""
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def session_rate_limit():
    """Rate limiting decorator for session management endpoints."""
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator


class AdvancedRateLimiter:
    """Advanced rate limiting with custom logic and monitoring."""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis_client = redis_client
        self.logger = logging.getLogger(__name__)
    
    def check_suspicious_activity(self, client_id: str) -> bool:
        """
        Check for suspicious activity patterns.
        
        Args:
            client_id: Client identifier
            
        Returns:
            bool: True if suspicious activity detected
        """
        try:
            # Check for rapid successive failures
            failure_key = f"auth_failures:{client_id}"
            failures = self.redis_client.get(failure_key)
            
            if failures and int(failures) > 5:
                self.logger.warning(f"Suspicious activity detected for {client_id}: {failures} failures")
                return True
            
            # Check for unusual request patterns
            request_key = f"request_count:{client_id}"
            request_count = self.redis_client.get(request_key)
            
            if request_count and int(request_count) > 100:
                self.logger.warning(f"High request volume for {client_id}: {request_count} requests")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking suspicious activity: {e}")
            return False
    
    def record_auth_failure(self, client_id: str):
        """
        Record authentication failure for monitoring.
        
        Args:
            client_id: Client identifier
        """
        try:
            failure_key = f"auth_failures:{client_id}"
            self.redis_client.incr(failure_key)
            self.redis_client.expire(failure_key, 3600)  # 1 hour expiry
        except Exception as e:
            self.logger.error(f"Error recording auth failure: {e}")
    
    def record_auth_success(self, client_id: str):
        """
        Record authentication success and reset failure counter.
        
        Args:
            client_id: Client identifier
        """
        try:
            failure_key = f"auth_failures:{client_id}"
            self.redis_client.delete(failure_key)
        except Exception as e:
            self.logger.error(f"Error recording auth success: {e}")
    
    def get_rate_limit_stats(self, client_id: str) -> Dict[str, Any]:
        """
        Get rate limiting statistics for a client.
        
        Args:
            client_id: Client identifier
            
        Returns:
            Dict: Rate limiting statistics
        """
        try:
            stats = {
                'client_id': client_id,
                'auth_failures': self.redis_client.get(f"auth_failures:{client_id}") or 0,
                'request_count': self.redis_client.get(f"request_count:{client_id}") or 0,
                'last_request': self.redis_client.get(f"last_request:{client_id}") or None,
                'suspicious_activity': self.check_suspicious_activity(client_id)
            }
            return stats
        except Exception as e:
            self.logger.error(f"Error getting rate limit stats: {e}")
            return {'error': str(e)}


# Advanced rate limiting with custom logic
def get_advanced_rate_limiter():
    """
    Get an instance of AdvancedRateLimiter with Redis client.
    
    Returns:
        AdvancedRateLimiter: Configured rate limiter instance
    """
    from utils.redis_utils import get_redis_client
    redis_client = get_redis_client()
    return AdvancedRateLimiter(redis_client)