# Testing Infrastructure

This document describes the comprehensive testing infrastructure for the ECC Passwordless MFA system.

## Overview

The testing infrastructure includes:
- **Unit Tests**: Testing individual functions and components
- **Integration Tests**: Testing API endpoints and component interactions
- **Security Tests**: Testing security properties and vulnerability prevention
- **Frontend Tests**: Testing React components and services
- **Backend Tests**: Testing Flask endpoints and database operations

## Test Structure

```
├── backend/
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py              # Pytest configuration and fixtures
│   │   ├── test_crypto.py           # Cryptographic operations tests
│   │   ├── test_auth_endpoints.py   # Authentication endpoint tests
│   │   ├── test_database.py         # Database operation tests
│   │   └── test_security.py         # Security-focused tests
│   ├── pytest.ini                   # Pytest configuration
│   └── run_tests.py                 # Test runner script
├── frontend/
│   ├── src/tests/
│   │   ├── __init__.py
│   │   ├── setup.ts                 # Test setup and mocks
│   │   ├── crypto.test.ts           # Frontend crypto service tests
│   │   └── api.test.ts              # Frontend API service tests
│   └── package.json                 # Updated with test scripts
└── TESTING.md                       # This file
```

## Backend Testing

### Prerequisites

Install test dependencies:
```bash
cd backend
pip install -r requirements.txt
```

### Running Tests

#### All Tests
```bash
cd backend
python run_tests.py
```

#### Specific Test Types
```bash
# Unit tests only
python run_tests.py unit

# Integration tests only
python run_tests.py integration

# Security tests only
python run_tests.py security

# All tests with coverage
python run_tests.py all
```

#### Direct Pytest Commands
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov=crypto --cov=database --cov-report=html

# Run specific test file
pytest tests/test_crypto.py

# Run tests with markers
pytest -m "unit"
pytest -m "integration"
pytest -m "security"
```

### Test Categories

#### 1. Cryptographic Tests (`test_crypto.py`)
- **ECC Operations**: Key generation, serialization, deserialization
- **ECDSA Operations**: Signature creation and verification
- **ECDH Operations**: Shared secret derivation
- **Security Properties**: Key uniqueness, entropy testing

#### 2. Authentication Endpoint Tests (`test_auth_endpoints.py`)
- **Registration**: User registration with validation
- **Authentication**: Challenge-response flow
- **Session Management**: ECDH key exchange and secure data
- **Device Management**: CRUD operations for devices
- **Recovery**: Account recovery flow

#### 3. Database Tests (`test_database.py`)
- **User Operations**: Create, retrieve, update users
- **Device Operations**: Device management
- **Session Operations**: Session tracking
- **Auth Logging**: Authentication event logging
- **Relationships**: Foreign key constraints and cascades

#### 4. Security Tests (`test_security.py`)
- **Security Headers**: HTTP security headers validation
- **Input Validation**: SQL injection, XSS prevention
- **Authentication Security**: Nonce expiration, token validation
- **Cryptographic Security**: Key uniqueness, signature verification
- **Rate Limiting**: Brute force protection
- **Error Handling**: Information disclosure prevention

### Test Fixtures

The `conftest.py` file provides common test fixtures:
- `test_app`: Flask test application
- `client`: Test client for making requests
- `mock_redis`: Mocked Redis client
- `sample_user`: Sample user for testing
- `sample_device`: Sample device for testing
- `auth_token`: Valid JWT token
- `sample_key_pair`: ECC key pair for testing
- `sample_nonce`: Test nonce
- `sample_signature`: Valid signature for testing

## Frontend Testing

### Prerequisites

Install dependencies:
```bash
cd frontend
npm install
```

### Running Tests

#### All Tests
```bash
npm test
```

#### With Coverage
```bash
npm run test:coverage
```

#### CI Mode (no watch)
```bash
npm run test:ci
```

### Test Categories

#### 1. Crypto Service Tests (`crypto.test.ts`)
- **Key Generation**: ECDSA and ECDH key pair generation
- **Key Export/Import**: PEM format handling
- **Signing**: Message signing with ECDSA
- **Encryption**: AES-GCM encryption/decryption
- **Key Exchange**: ECDH shared secret derivation

#### 2. API Service Tests (`api.test.ts`)
- **Authentication**: Registration, challenge, verification
- **Session Management**: ECDH exchange, secure data
- **Device Management**: CRUD operations
- **Recovery**: Account recovery flow
- **Error Handling**: Network and API errors

### Test Setup

The `setup.ts` file provides:
- **Web Crypto API Mock**: Mocked cryptographic functions
- **localStorage Mock**: Mocked browser storage
- **IndexedDB Mock**: Mocked database
- **Fetch Mock**: Mocked HTTP requests
- **Console Mock**: Reduced test noise

## Coverage Requirements

### Backend Coverage
- **Lines**: 70% minimum
- **Functions**: 70% minimum
- **Branches**: 70% minimum
- **Statements**: 70% minimum

### Frontend Coverage
- **Lines**: 70% minimum
- **Functions**: 70% minimum
- **Branches**: 70% minimum
- **Statements**: 70% minimum

## Security Testing

### Automated Security Tests
- **Input Validation**: SQL injection, XSS attempts
- **Authentication**: Token expiration, signature verification
- **Cryptographic**: Key uniqueness, signature security
- **Rate Limiting**: Brute force protection
- **Error Handling**: Information disclosure

### Manual Security Testing
- **OWASP ZAP**: Automated security scanning
- **Penetration Testing**: Manual vulnerability assessment
- **Code Review**: Security-focused code analysis

## Continuous Integration

### GitHub Actions (Recommended)
```yaml
name: Tests
on: [push, pull_request]
jobs:
  backend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.9
      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt
      - name: Run tests
        run: |
          cd backend
          python run_tests.py all

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Node.js
        uses: actions/setup-node@v2
        with:
          node-version: 16
      - name: Install dependencies
        run: |
          cd frontend
          npm install
      - name: Run tests
        run: |
          cd frontend
          npm run test:ci
```

## Test Data Management

### Database
- Uses SQLite in-memory database for tests
- Automatic cleanup after each test
- Isolated test data per test

### Redis
- Mocked Redis client for tests
- No external Redis dependency
- Configurable mock responses

### Files
- Temporary files cleaned up automatically
- No persistent test artifacts
- Isolated test environments

## Best Practices

### Writing Tests
1. **Arrange-Act-Assert**: Clear test structure
2. **Descriptive Names**: Test names explain what is being tested
3. **Isolation**: Tests don't depend on each other
4. **Mocking**: External dependencies are mocked
5. **Coverage**: Aim for high test coverage

### Test Organization
1. **Group Related Tests**: Use describe blocks
2. **Test Categories**: Unit, integration, security
3. **Fixtures**: Reuse common test data
4. **Cleanup**: Always clean up after tests

### Security Testing
1. **Input Validation**: Test malicious inputs
2. **Authentication**: Test token validation
3. **Authorization**: Test access control
4. **Cryptographic**: Test key security
5. **Error Handling**: Test information disclosure

## Troubleshooting

### Common Issues

#### Backend Tests
```bash
# Import errors
pip install -r requirements.txt

# Database connection issues
export DATABASE_URL=sqlite:///:memory:

# Redis connection issues
export REDIS_URL=redis://localhost:6379/1
```

#### Frontend Tests
```bash
# Module not found
npm install

# Web Crypto API not available
# Check setup.ts mocks

# localStorage not available
# Check setup.ts mocks
```

### Debugging
```bash
# Backend with debug output
pytest -v -s

# Frontend with debug output
npm test -- --verbose
```

## Performance Testing

### Load Testing
```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:5000/auth/challenge

# Using wrk
wrk -t12 -c400 -d30s http://localhost:5000/auth/challenge
```

### Memory Testing
```bash
# Python memory profiling
pip install memory-profiler
python -m memory_profiler backend/app.py
```

## Reporting

### Coverage Reports
- **HTML**: `backend/htmlcov/index.html`
- **XML**: `backend/coverage.xml`
- **Terminal**: Coverage summary in test output

### Test Reports
- **JUnit XML**: For CI integration
- **HTML**: Detailed test results
- **Console**: Real-time test progress

## Future Enhancements

### Planned Improvements
1. **E2E Tests**: Full user flow testing
2. **Performance Tests**: Automated performance testing
3. **Visual Regression**: UI component testing
4. **Accessibility Tests**: WCAG compliance testing
5. **Mobile Testing**: Mobile device testing

### Tools Integration
1. **SonarQube**: Code quality analysis
2. **Snyk**: Dependency vulnerability scanning
3. **OWASP ZAP**: Automated security testing
4. **Lighthouse**: Performance and accessibility testing 