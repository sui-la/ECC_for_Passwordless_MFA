"""
Redis utility functions for ECC Passwordless MFA.
Consolidates Redis client and verification code generation functions.
"""

import redis
import random
import string
from flask import current_app


def get_redis_client():
    """Get Redis client from app context."""
    return redis.StrictRedis.from_url(current_app.config['REDIS_URL'], decode_responses=True)


def generate_verification_code():
    """Generate a random 6-digit verification code."""
    return ''.join(random.choices(string.digits, k=6))
