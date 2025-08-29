# 📚 API Documentation

## Overview

The ECC Passwordless MFA API provides a comprehensive RESTful interface for passwordless authentication using Elliptic Curve Cryptography. All endpoints return JSON responses and use standard HTTP status codes.

**Base URL**: `http://localhost:5000`
**API Documentation**: `http://localhost:5000/api/docs` (Interactive Swagger UI)

## Authentication

### JWT Token Authentication
Most endpoints require a JWT token in the Authorization header:
```
Authorization: Bearer <jwt_token>
```

### ECDH Key Exchange
For secure communication, establish ECDH key exchange:
1. Client generates ephemeral ECDH key pair
2. Client sends public key to `/session/ecdh`
3. Server responds with its public key
4. Both parties derive shared secret
5. Use shared secret for AES-GCM encryption

## Core Endpoints

### 1. User Registration

#### `POST /register`
Register a new user with their first device.

**Request Body:**
```json
{
  "email": "user@example.com",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "device_name": "My Device"
}
```

**Response (201 Created):**
```json
{
  "message": "User registered successfully. Please check your email for verification code.",
  "device_id": "uuid-string",
  "requires_verification": true
}
```

**Response (409 Conflict):**
```json
{
  "error": "User already registered.",
  "message": "An account with this email already exists. Please use the authentication flow to sign in.",
  "code": "USER_ALREADY_EXISTS"
}
```

### 2. Authentication Challenge

#### `POST /auth/challenge`
Generate a cryptographic challenge for authentication.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "nonce": "random-challenge-string"
}
```

**Response (404 Not Found):**
```json
{
  "error": "User not found."
}
```

### 3. Authentication Verification

#### `POST /auth/verify`
Verify the user's signature and establish a session.

**Request Body:**
```json
{
  "email": "user@example.com",
  "signature": "base64-encoded-signature",
  "device_id": "optional-device-id"
}
```

**Response (200 OK):**
```json
{
  "token": "jwt-token",
  "server_ecdh_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "session_id": "session-uuid"
}
```

**Response (403 Forbidden - Email Verification Required):**
```json
{
  "error": "Email verification required.",
  "requires_verification": true,
  "message": "Please check your email for verification code."
}
```

### 4. User Profile

#### `GET /profile`
Get the authenticated user's profile information.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200 OK):**
```json
{
  "email": "user@example.com",
  "last_login": "2025-07-31 17:30:00 UTC",
  "created_at": "2025-07-31 10:00:00 UTC"
}
```

## Device Management

### 1. Get User Devices

#### `GET /devices`
Get all devices for the authenticated user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200 OK):**
```json
{
  "devices": [
    {
      "device_id": "uuid-string",
      "device_name": "My Device",
      "created_at": "2025-07-31 10:00:00 UTC",
      "last_used": "2025-07-31 17:30:00 UTC",
      "is_active": true
    }
  ]
}
```

### 2. Add New Device

#### `POST /devices`
Add a new device for the authenticated user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "device_name": "New Device"
}
```

**Response (201 Created):**
```json
{
  "message": "Device added successfully.",
  "device_id": "uuid-string",
  "device_name": "New Device"
}
```

### 3. Remove Device

#### `DELETE /devices/{device_id}`
Remove a device for the authenticated user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200 OK):**
```json
{
  "message": "Device removed successfully."
}
```

### 4. Get Device Public Key

#### `GET /devices/{device_id}/public-key`
Get the public key for a specific device.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200 OK):**
```json
{
  "device_id": "uuid-string",
  "device_name": "My Device",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

## Secure Session Management

### 1. ECDH Key Exchange

#### `POST /session/ecdh`
Establish ECDH key exchange for secure communication.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "client_ecdh_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

**Response (200 OK):**
```json
{
  "message": "Shared secret established."
}
```

## Secure Messaging

### 1. Send Secure Message

#### `POST /session/send-secure-message`
Send an encrypted message to another user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "recipient_email": "recipient@example.com",
  "encrypted_message": "base64-encoded-encrypted-message",
  "message_iv": "base64-encoded-iv",
  "message_id": "unique-message-id"
}
```

**Response (200 OK):**
```json
{
  "message": "Secure message sent successfully.",
  "message_id": "unique-message-id"
}
```

### 2. Receive Secure Messages

#### `GET /session/receive-secure-messages`
Get all encrypted messages for the authenticated user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200 OK):**
```json
{
  "messages": [
    {
      "message_id": "unique-message-id",
      "sender_email": "sender@example.com",
      "encrypted_message": "base64-encoded-encrypted-message",
      "message_iv": "base64-encoded-iv",
      "timestamp": "2025-07-31T17:30:00Z",
      "session_id": "session-uuid"
    }
  ],
  "count": 1
}
```

### 3. Delete Secure Message

#### `DELETE /session/delete-secure-message/{message_id}`
Delete a specific encrypted message.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200 OK):**
```json
{
  "message": "Message deleted successfully."
}
```

### 4. Update Message Encryption

#### `PUT /session/update-message-encryption/{message_id}`
Update the encryption of an existing message.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "encrypted_message": "new-base64-encoded-encrypted-message",
  "message_iv": "new-base64-encoded-iv",
  "new_message_id": "new-unique-message-id"
}
```

**Response (200 OK):**
```json
{
  "message": "Message encryption updated successfully.",
  "new_message_id": "new-unique-message-id"
}
```

## Account Recovery

### 1. Initiate Recovery

#### `POST /recovery/initiate`
Initiate account recovery process.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "message": "Recovery email sent successfully."
}
```

### 2. Verify Recovery Token

#### `POST /recovery/verify-token`
Verify recovery token and get user info.

**Request Body:**
```json
{
  "recovery_token": "recovery-token-uuid"
}
```

**Response (200 OK):**
```json
{
  "email": "user@example.com",
  "user_id": "user-uuid",
  "recovery_token": "recovery-token-uuid"
}
```

### 3. Complete Recovery

#### `POST /recovery/complete`
Complete account recovery with new device.

**Request Body:**
```json
{
  "recovery_token": "recovery-token-uuid",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "device_name": "Recovery Device"
}
```

**Response (200 OK):**
```json
{
  "message": "Account recovery completed successfully.",
  "device_id": "device-uuid"
}
```

## Email Verification

### 1. Send Verification Code

#### `POST /email/send-verification`
Send a verification code to user's email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "message": "Verification code sent successfully."
}
```

### 2. Verify Email Code

#### `POST /email/verify-code`
Verify the email verification code.

**Request Body:**
```json
{
  "email": "user@example.com",
  "verification_code": "123456"
}
```

**Response (200 OK):**
```json
{
  "message": "Email verification successful. You can now authenticate."
}
```

## System Endpoints

### 1. Health Check

#### `GET /health`
Basic system health check.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "database": "healthy",
  "redis": "healthy",
  "rate_limiting": "healthy",
  "timestamp": "2025-07-31T17:30:00Z",
  "version": "v1",
  "check_duration_ms": 12.87
}
```

### 2. Security Information

#### `GET /security`
Get security configuration information.

**Response (200 OK):**
```json
{
  "environment": "development",
  "security_headers_count": 8,
  "csp_validation": "valid",
  "hsts_enabled": true,
  "recommendations": [
    "Enable HTTPS in production",
    "Configure CSP for your domain"
  ]
}
```

### 3. Log Statistics

#### `GET /logs/stats`
Get logging statistics.

**Response (200 OK):**
```json
{
  "total_logs": 1250,
  "security_logs": 45,
  "audit_logs": 230,
  "error_logs": 12,
  "log_levels": {
    "INFO": 800,
    "WARNING": 150,
    "ERROR": 12,
    "DEBUG": 288
  }
}
```

## Monitoring Endpoints

### 1. Comprehensive Health Check

#### `GET /api/monitoring/health/comprehensive`
Get comprehensive health status with all metrics.

**Response (200 OK):**
```json
{
  "overall": "healthy",
  "version": "v1",
  "timestamp": "2025-07-31T17:30:00Z",
  "check_duration_ms": 45.23,
  "services": {
    "database": {
      "status": "healthy",
      "response_time_ms": 8.5,
      "user_count": 25,
      "device_count": 45
    },
    "redis": {
      "status": "healthy",
      "response_time_ms": 2.1
    },
    "rate_limiting": {
      "status": "healthy",
      "active_limits": 3
    }
  },
  "system": {
    "cpu_usage": 15.2,
    "memory_usage": 45.8,
    "disk_usage": 23.1
  }
}
```

### 2. System Status

#### `GET /api/monitoring/system/status`
Get real-time system status.

**Response (200 OK):**
```json
{
  "system_status": {
    "cpu": {
      "usage_percent": 15.2,
      "count": 8,
      "frequency_mhz": 2400
    },
    "memory": {
      "total_gb": 16.0,
      "used_gb": 7.3,
      "available_gb": 8.7,
      "usage_percent": 45.8
    },
    "disk": {
      "total_gb": 500.0,
      "used_gb": 115.5,
      "free_gb": 384.5,
      "usage_percent": 23.1
    },
    "network": {
      "bytes_sent": 1024000,
      "bytes_recv": 2048000
    }
  },
  "timestamp": "2025-07-31T17:30:00Z"
}
```

### 3. Performance Report

#### `GET /api/monitoring/performance`
Get performance monitoring report.

**Response (200 OK):**
```json
{
  "performance_metrics": {
    "avg_response_time_ms": 85.2,
    "max_response_time_ms": 450.1,
    "requests_per_minute": 120,
    "error_rate": 0.5
  },
  "slow_queries": [
    {
      "query": "SELECT * FROM users WHERE email = ?",
      "execution_time_ms": 45.2,
      "frequency": 5
    }
  ],
  "recommendations": [
    "Consider adding index on users.email",
    "Optimize session cleanup queries"
  ]
}
```

## Database Optimization Endpoints

### 1. Optimization Score

#### `GET /api/database/optimization/score`
Get current database optimization score.

**Response (200 OK):**
```json
{
  "optimization_score": 100.0,
  "timestamp": "2025-07-31T17:30:00Z"
}
```

### 2. Optimization Report

#### `GET /api/database/optimization/report`
Get comprehensive database optimization report.

**Response (200 OK):**
```json
{
  "optimization_score": 100.0,
  "analysis_duration_ms": 36.22,
  "index_analysis": {
    "users": {
      "count": 3,
      "indexes": [
        {
          "name": "idx_users_email",
          "column_names": ["email"],
          "unique": false
        }
      ]
    }
  },
  "index_recommendations": [
    {
      "table": "users",
      "columns": ["email"],
      "priority": "high",
      "reason": "Frequently used in WHERE clauses"
    }
  ],
  "pool_recommendations": {
    "recommended_config": {
      "pool_size": 10,
      "max_overflow": 5,
      "pool_pre_ping": true
    }
  }
}
```

### 3. Index Scripts

#### `GET /api/database/optimization/indexes`
Get SQL script for recommended indexes.

**Response (200 OK):**
```json
{
  "index_script": "-- Database Index Optimization Script\n\n-- Users table indexes\nCREATE INDEX idx_users_email ON users(email);\nCREATE INDEX idx_users_registration_date ON users(registration_date);\n\n-- Devices table indexes\nCREATE INDEX idx_devices_user_id ON devices(user_id);\nCREATE INDEX idx_devices_device_id_user_id ON devices(device_id, user_id);",
  "timestamp": "2025-07-31T17:30:00Z"
}
```

## API Documentation Endpoints

### 1. Interactive Documentation

#### `GET /api/docs`
Interactive Swagger UI documentation.

**Response**: HTML page with interactive API documentation.

### 2. OpenAPI Specification

#### `GET /api/spec`
Get OpenAPI specification in JSON format.

**Response (200 OK):**
```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "ECC Passwordless MFA API",
    "version": "1.0.0",
    "description": "Passwordless authentication using ECC"
  },
  "paths": {
    "/register": {
      "post": {
        "summary": "Register new user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "email": {
                    "type": "string",
                    "format": "email"
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### 3. API Endpoints List

#### `GET /api/endpoints`
Get list of all API endpoints.

**Response (200 OK):**
```json
{
  "endpoints": {
    "Authentication": [
      "POST /register",
      "POST /auth/challenge",
      "POST /auth/verify"
    ],
    "User Management": [
      "GET /profile",
      "GET /devices",
      "POST /devices"
    ],
    "System": [
      "GET /health",
      "GET /security",
      "GET /logs/stats"
    ]
  },
  "total_endpoints": 25,
  "categories": ["Authentication", "User Management", "System"]
}
```

## Error Responses

All endpoints return consistent error responses:

### Validation Error (400 Bad Request)
```json
{
  "error": "Validation error",
  "message": "Required field 'email' is missing",
  "code": "VALIDATION_ERROR",
  "request_id": "req-12345",
  "timestamp": "2025-07-31T17:30:00Z"
}
```

### Authentication Error (401 Unauthorized)
```json
{
  "error": "Authentication error",
  "message": "Invalid token",
  "code": "AUTHENTICATION_ERROR",
  "request_id": "req-12345",
  "timestamp": "2025-07-31T17:30:00Z"
}
```

### Rate Limit Error (429 Too Many Requests)
```json
{
  "error": "Rate limit exceeded",
  "message": "Too many authentication attempts",
  "code": "RATE_LIMIT_ERROR",
  "request_id": "req-12345",
  "timestamp": "2025-07-31T17:30:00Z",
  "retry_after": 60
}
```

### Server Error (500 Internal Server Error)
```json
{
  "error": "Internal server error",
  "message": "An unexpected error occurred",
  "code": "INTERNAL_ERROR",
  "request_id": "req-12345",
  "timestamp": "2025-07-31T17:30:00Z"
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Authentication**: 5 attempts per minute
- **Registration**: 3 attempts per hour
- **Recovery**: 3 attempts per hour
- **Device Management**: 10 operations per minute
- **Email Verification**: 5 attempts per minute

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 3
X-RateLimit-Reset: 1640995200
```

## Security Headers

All responses include security headers:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## Testing Examples

### cURL Examples

**Register a new user:**
```bash
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "device_name": "Test Device"
  }'
```

**Get authentication challenge:**
```bash
curl -X POST http://localhost:5000/auth/challenge \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'
```

**Verify authentication:**
```bash
curl -X POST http://localhost:5000/auth/verify \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "signature": "base64-encoded-signature"
  }'
```

**Get user profile:**
```bash
curl -X GET http://localhost:5000/profile \
  -H "Authorization: Bearer <jwt_token>"
```

### JavaScript Examples

**Register user:**
```javascript
const response = await fetch('http://localhost:5000/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'test@example.com',
    public_key_pem: publicKeyPem,
    device_name: 'My Device'
  })
});

const data = await response.json();
```

**Authenticate user:**
```javascript
// Get challenge
const challengeResponse = await fetch('http://localhost:5000/auth/challenge', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'test@example.com'
  })
});

const { nonce } = await challengeResponse.json();

// Sign challenge and verify
const signature = await signChallenge(nonce, privateKey);
const verifyResponse = await fetch('http://localhost:5000/auth/verify', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'test@example.com',
    signature: signature
  })
});

const { token } = await verifyResponse.json();
```

## Best Practices

1. **Always use HTTPS in production**
2. **Store JWT tokens securely**
3. **Implement proper error handling**
4. **Use rate limiting on client side**
5. **Validate all inputs**
6. **Log security events**
7. **Monitor API usage**
8. **Keep dependencies updated**
9. **Use strong cryptographic keys**
10. **Implement proper session management**

---

This API provides a complete, secure, and production-ready interface for passwordless authentication using modern cryptographic standards. 