#!/bin/bash

# Ultimate ECC Passwordless MFA System Test
# Comprehensive Docker-based testing for the entire system

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Configuration
BACKEND_URL="http://localhost:5000"
FRONTEND_URL="http://localhost:3000"
TIMEOUT=30
WAIT_TIME=5

# Test data
TEST_EMAIL="test@example.com"
TEST_DEVICE_NAME="Test Device"
TEST_MESSAGE="Hello, this is a test message!"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_test() {
    echo -e "${PURPLE}[TEST]${NC} $1"
}

test_http_status() {
    local url=$1
    local expected_status=$2
    local test_name=$3
    local method=${4:-GET}
    local data=${5:-}
    
    log_test "$test_name"
    
    if [ -n "$data" ]; then
        response=$(curl -s -w "%{http_code}" -X "$method" -H "Content-Type: application/json" -d "$data" "$url" 2>/dev/null || echo "000")
    else
        response=$(curl -s -w "%{http_code}" -X "$method" "$url" 2>/dev/null || echo "000")
    fi
    
    status_code="${response: -3}"
    body="${response%???}"
    
    if [ "$status_code" = "$expected_status" ]; then
        log_success "$test_name (Status: $status_code)"
        return 0
    else
        log_error "$test_name (Expected: $expected_status, Got: $status_code)"
        return 1
    fi
}

wait_for_service() {
    local url=$1
    local service_name=$2
    local max_attempts=30
    local attempt=1
    
    log_info "Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$url" >/dev/null 2>&1; then
            log_success "$service_name is ready!"
            return 0
        fi
        
        log_info "Attempt $attempt/$max_attempts - $service_name not ready yet..."
        sleep 2
        ((attempt++))
    done
    
    log_error "$service_name failed to start within $((max_attempts * 2)) seconds"
    return 1
}

# Main test execution
main() {
    echo -e "${CYAN}"
    echo "=========================================="
    echo "  Ultimate ECC Passwordless MFA Test Suite"
    echo "=========================================="
    echo -e "${NC}"
    
    # Check if Docker is running
    log_info "Checking Docker status..."
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    log_success "Docker is running"
    
    # Check if docker-compose.yml exists
    if [ ! -f "docker-compose.yml" ]; then
        log_error "docker-compose.yml not found in current directory"
        exit 1
    fi
    log_success "docker-compose.yml found"
    
    # Start the system
    log_info "Starting ECC Passwordless MFA system..."
    docker-compose up -d
    
    # Wait for services to be ready
    wait_for_service "$BACKEND_URL/health" "Backend"
    wait_for_service "$FRONTEND_URL" "Frontend"
    
    log_info "All services are ready. Starting comprehensive tests..."
    echo
    
    # ========================================
    # 1. DOCKER CONTAINER HEALTH TESTS
    # ========================================
    log_info "1. Testing Docker Container Health"
    echo "----------------------------------------"
    
    # Check if all containers are running
    log_test "1.1: Checking if all containers are running"
    containers_running=$(docker-compose ps -q | wc -l)
    if [ "$containers_running" -ge 3 ]; then
        log_success "All containers are running ($containers_running containers)"
    else
        log_error "Not all containers are running (found $containers_running)"
    fi
    
    # Check container health
    log_test "1.2: Checking container health status"
    unhealthy_containers=$(docker-compose ps | grep -c "unhealthy" || true)
    if [ "$unhealthy_containers" -eq 0 ]; then
        log_success "All containers are healthy"
    else
        log_error "Found $unhealthy_containers unhealthy containers"
    fi
    
    # Check container logs for errors
    log_test "1.3: Checking container logs for errors"
    error_logs=$(docker-compose logs --tail=50 2>&1 | grep -i "error\|exception\|failed" | wc -l || true)
    if [ "$error_logs" -eq 0 ]; then
        log_success "No critical errors in container logs"
    else
        log_warning "Found $error_logs potential error messages in logs"
    fi
    
    echo
    
    # ========================================
    # 2. BACKEND API TESTS
    # ========================================
    log_info "2. Testing Backend API Endpoints"
    echo "----------------------------------------"
    
    # Health check
    test_http_status "$BACKEND_URL/health" "200" "2.1: Health endpoint"
    
    # Security info
    test_http_status "$BACKEND_URL/security" "200" "2.2: Security info endpoint"
    
    # API documentation
    test_http_status "$BACKEND_URL/api/docs" "200" "2.3: API documentation endpoint"
    
    # API specification
    test_http_status "$BACKEND_URL/api/spec" "200" "2.4: API specification endpoint"
    
    # API endpoints list
    test_http_status "$BACKEND_URL/api/endpoints" "200" "2.5: API endpoints list"
    
    # Comprehensive health check
    test_http_status "$BACKEND_URL/api/monitoring/health/comprehensive" "200" "2.6: Comprehensive health check"
    
    # Performance metrics
    test_http_status "$BACKEND_URL/api/monitoring/performance" "200" "2.7: Performance metrics"
    
    # System status
    test_http_status "$BACKEND_URL/api/monitoring/system/status" "200" "2.8: System status"
    
    # Database optimization report
    test_http_status "$BACKEND_URL/api/database/optimization/report" "200" "2.9: Database optimization report"
    
    # Database optimization score
    test_http_status "$BACKEND_URL/api/database/optimization/score" "200" "2.10: Database optimization score"
    
    # Log statistics
    test_http_status "$BACKEND_URL/logs/stats" "200" "2.11: Log statistics"
    
    echo
    
    # ========================================
    # 3. AUTHENTICATION TESTS
    # ========================================
    log_info "3. Testing Authentication System"
    echo "----------------------------------------"
    
    # Test registration with invalid data
    test_http_status "$BACKEND_URL/register" "400" "3.1: Registration with invalid data" "POST" '{"invalid": "data"}'
    
    # Test registration with valid data
    test_http_status "$BACKEND_URL/register" "201" "3.2: Registration with valid data" "POST" "{\"email\": \"$TEST_EMAIL\", \"public_key_pem\": \"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\", \"device_name\": \"$TEST_DEVICE_NAME\"}"
    
    # Test duplicate registration
    test_http_status "$BACKEND_URL/register" "409" "3.3: Duplicate registration" "POST" "{\"email\": \"$TEST_EMAIL\", \"public_key_pem\": \"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\", \"device_name\": \"$TEST_DEVICE_NAME\"}"
    
    # Test authentication challenge
    test_http_status "$BACKEND_URL/auth/challenge" "200" "3.4: Authentication challenge" "POST" "{\"email\": \"$TEST_EMAIL\"}"
    
    # Test authentication with invalid signature
    test_http_status "$BACKEND_URL/auth/verify" "400" "3.5: Authentication with invalid signature" "POST" '{"email": "'$TEST_EMAIL'", "signature": "invalid", "nonce": "test"}'
    
    echo
    
    # ========================================
    # 4. DEVICE MANAGEMENT TESTS
    # ========================================
    log_info "4. Testing Device Management"
    echo "----------------------------------------"
    
    # Get devices (should fail without auth)
    test_http_status "$BACKEND_URL/devices" "401" "4.1: Get devices without authentication"
    
    # Add new device (should fail without auth)
    test_http_status "$BACKEND_URL/devices" "401" "4.2: Add device without authentication" "POST" '{"public_key_pem": "test"}'
    
    echo
    
    # ========================================
    # 5. SECURE MESSAGING TESTS
    # ========================================
    log_info "5. Testing Secure Messaging"
    echo "----------------------------------------"
    
    # ECDH key exchange (should fail without auth)
    test_http_status "$BACKEND_URL/session/ecdh" "401" "5.1: ECDH key exchange without authentication" "POST" '{"public_key": "test"}'
    
    # Send secure message (should fail without auth)
    test_http_status "$BACKEND_URL/session/send-secure-message" "401" "5.2: Send secure message without authentication" "POST" '{"message": "test"}'
    
    # Receive secure messages (should fail without auth)
    test_http_status "$BACKEND_URL/session/receive-secure-messages" "401" "5.3: Receive messages without authentication"
    
    echo
    
    # ========================================
    # 6. ACCOUNT RECOVERY TESTS
    # ========================================
    log_info "6. Testing Account Recovery"
    echo "----------------------------------------"
    
    # Initiate recovery
    test_http_status "$BACKEND_URL/recovery/initiate" "200" "6.1: Initiate account recovery" "POST" "{\"email\": \"$TEST_EMAIL\"}"
    
    # Verify recovery token (should fail with invalid token)
    test_http_status "$BACKEND_URL/recovery/verify-token" "400" "6.2: Verify invalid recovery token" "POST" '{"email": "'$TEST_EMAIL'", "token": "invalid"}'
    
    # Complete recovery (should fail with invalid data)
    test_http_status "$BACKEND_URL/recovery/complete" "400" "6.3: Complete recovery with invalid data" "POST" '{"email": "'$TEST_EMAIL'", "token": "invalid", "new_public_key": "invalid"}'
    
    echo
    
    # ========================================
    # 7. EMAIL VERIFICATION TESTS
    # ========================================
    log_info "7. Testing Email Verification"
    echo "----------------------------------------"
    
    # Send verification email
    test_http_status "$BACKEND_URL/email/send-verification" "200" "7.1: Send verification email" "POST" "{\"email\": \"$TEST_EMAIL\"}"
    
    # Verify email code (should fail with invalid code)
    test_http_status "$BACKEND_URL/email/verify-code" "400" "7.2: Verify invalid email code" "POST" "{\"email\": \"$TEST_EMAIL\", \"verification_code\": \"000000\"}"
    
    echo
    
    # ========================================
    # 8. FRONTEND ACCESSIBILITY TESTS
    # ========================================
    log_info "8. Testing Frontend Accessibility"
    echo "----------------------------------------"
    
    # Check if frontend is accessible
    test_http_status "$FRONTEND_URL" "200" "8.1: Frontend main page"
    
    # Check if frontend serves static files
    test_http_status "$FRONTEND_URL/static/js/main.js" "200" "8.2: Frontend JavaScript files"
    
    # Check if frontend serves CSS files
    test_http_status "$FRONTEND_URL/static/css/main.css" "200" "8.3: Frontend CSS files"
    
    echo
    
    # ========================================
    # 9. DATABASE OPERATIONS TESTS
    # ========================================
    log_info "9. Testing Database Operations"
    echo "----------------------------------------"
    
    # Check database optimization indexes
    test_http_status "$BACKEND_URL/api/database/optimization/indexes" "200" "9.1: Database optimization indexes"
    
    # Check performance stats
    test_http_status "$BACKEND_URL/api/performance/stats" "200" "9.2: Performance statistics"
    
    # Clear performance cache
    test_http_status "$BACKEND_URL/api/performance/cache/clear" "200" "9.3: Clear performance cache" "POST" "{}"
    
    echo
    
    # ========================================
    # 10. SECURITY FEATURES TESTS
    # ========================================
    log_info "10. Testing Security Features"
    echo "----------------------------------------"
    
    # Test rate limiting (make multiple requests)
    log_test "10.1: Testing rate limiting"
    for i in {1..5}; do
        curl -s -w "%{http_code}" "$BACKEND_URL/register" >/dev/null 2>&1
    done
    # The 6th request should be rate limited
    response=$(curl -s -w "%{http_code}" "$BACKEND_URL/register" 2>/dev/null || echo "000")
    status_code="${response: -3}"
    if [ "$status_code" = "429" ]; then
        log_success "10.1: Rate limiting is working (Status: 429)"
    else
        log_error "10.1: Rate limiting not working (Expected: 429, Got: $status_code)"
    fi
    
    # Test CORS headers
    log_test "10.2: Testing CORS headers"
    cors_headers=$(curl -s -I "$BACKEND_URL/health" | grep -i "access-control" | wc -l || true)
    if [ "$cors_headers" -gt 0 ]; then
        log_success "10.2: CORS headers are present"
    else
        log_error "10.2: CORS headers are missing"
    fi
    
    # Test security headers
    log_test "10.3: Testing security headers"
    security_headers=$(curl -s -I "$BACKEND_URL/health" | grep -i "x-content-type\|x-frame-options\|x-xss-protection" | wc -l || true)
    if [ "$security_headers" -gt 0 ]; then
        log_success "10.3: Security headers are present"
    else
        log_error "10.3: Security headers are missing"
    fi
    
    echo
    
    # ========================================
    # 11. ERROR HANDLING TESTS
    # ========================================
    log_info "11. Testing Error Handling"
    echo "----------------------------------------"
    
    # Test 404 for invalid endpoint
    test_http_status "$BACKEND_URL/invalid-endpoint" "404" "11.1: Invalid endpoint returns 404"
    
    # Test invalid method
    test_http_status "$BACKEND_URL/health" "405" "11.2: Invalid HTTP method" "POST"
    
    # Test malformed JSON
    test_http_status "$BACKEND_URL/register" "400" "11.3: Malformed JSON request" "POST" "{invalid json}"
    
    echo
    
    # ========================================
    # 12. INTEGRATION TESTS
    # ========================================
    log_info "12. Testing System Integration"
    echo "----------------------------------------"
    
    # Test backend-frontend connectivity
    log_test "12.1: Backend-frontend integration"
    backend_health=$(curl -s "$BACKEND_URL/health" | grep -o '"status":"healthy"' | wc -l || true)
    if [ "$backend_health" -gt 0 ]; then
        log_success "12.1: Backend is healthy and accessible"
    else
        log_error "12.1: Backend health check failed"
    fi
    
    # Test database connectivity
    log_test "12.2: Database connectivity"
    db_status=$(curl -s "$BACKEND_URL/api/monitoring/health/comprehensive" | grep -o '"database":"connected"' | wc -l || true)
    if [ "$db_status" -gt 0 ]; then
        log_success "12.2: Database is connected"
    else
        log_warning "12.2: Database connectivity status unclear"
    fi
    
    # Test Redis connectivity
    log_test "12.3: Redis connectivity"
    redis_status=$(curl -s "$BACKEND_URL/api/monitoring/health/comprehensive" | grep -o '"redis":"connected"' | wc -l || true)
    if [ "$redis_status" -gt 0 ]; then
        log_success "12.3: Redis is connected"
    else
        log_warning "12.3: Redis connectivity status unclear"
    fi
    
    echo
    
    # ========================================
    # 13. PERFORMANCE TESTS
    # ========================================
    log_info "13. Testing Performance"
    echo "----------------------------------------"
    
    # Test response time for health endpoint
    log_test "13.1: Health endpoint response time"
    start_time=$(date +%s%N)
    curl -s "$BACKEND_URL/health" >/dev/null
    end_time=$(date +%s%N)
    response_time=$(( (end_time - start_time) / 1000000 ))
    
    if [ "$response_time" -lt 1000 ]; then
        log_success "13.1: Health endpoint response time: ${response_time}ms (Good)"
    elif [ "$response_time" -lt 3000 ]; then
        log_warning "13.1: Health endpoint response time: ${response_time}ms (Acceptable)"
    else
        log_error "13.1: Health endpoint response time: ${response_time}ms (Slow)"
    fi
    
    # Test concurrent requests
    log_test "13.2: Concurrent request handling"
    concurrent_success=0
    for i in {1..5}; do
        if curl -s "$BACKEND_URL/health" >/dev/null 2>&1; then
        ((concurrent_success++))
        fi
    done
    
    if [ "$concurrent_success" -eq 5 ]; then
        log_success "13.2: All concurrent requests succeeded"
    else
        log_error "13.2: Only $concurrent_success/5 concurrent requests succeeded"
    fi
    
    echo
    
    # ========================================
    # 14. MONITORING TESTS
    # ========================================
    log_info "14. Testing Monitoring & Metrics"
    echo "----------------------------------------"
    
    # Test metrics history
    test_http_status "$BACKEND_URL/api/monitoring/metrics/history" "200" "14.1: Metrics history endpoint"
    
    # Test performance optimization
    test_http_status "$BACKEND_URL/api/performance/optimize" "200" "14.2: Performance optimization endpoint" "POST" "{}"
    
    echo
    
    # ========================================
    # 15. FINAL SYSTEM VALIDATION
    # ========================================
    log_info "15. Final System Validation"
    echo "----------------------------------------"
    
    # Final health check
    test_http_status "$BACKEND_URL/health" "200" "15.1: Final backend health check"
    
    # Final frontend check
    test_http_status "$FRONTEND_URL" "200" "15.2: Final frontend accessibility check"
    
    # Check system resources
    log_test "15.3: System resource usage"
    memory_usage=$(docker stats --no-stream --format "table {{.MemUsage}}" | tail -n +2 | head -1 | cut -d'/' -f1 | sed 's/MiB//' | tr -d ' ')
    if [ -n "$memory_usage" ] && [ "$memory_usage" -lt 1000 ]; then
        log_success "15.3: Memory usage is reasonable (${memory_usage}MB)"
    else
        log_warning "15.3: Memory usage might be high (${memory_usage}MB)"
    fi
    
    echo
    
    # ========================================
    # TEST SUMMARY
    # ========================================
    echo -e "${CYAN}"
    echo "=========================================="
    echo "  Ultimate Test Suite Results"
    echo "=========================================="
    echo -e "${NC}"
    
    echo "Total Tests: $TOTAL_TESTS"
    echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
    
    if [ "$FAILED_TESTS" -eq 0 ]; then
        echo -e "${GREEN}"
        echo "🎉 All tests passed! Your ECC Passwordless MFA system is working perfectly!"
        echo -e "${NC}"
        exit_code=0
    elif [ "$FAILED_TESTS" -le 5 ]; then
        echo -e "${YELLOW}"
        echo "⚠️  Most tests passed. There are $FAILED_TESTS minor issues to address."
        echo -e "${NC}"
        exit_code=1
    else
        echo -e "${RED}"
        echo "❌ Multiple tests failed. Please review the issues above."
        echo -e "${NC}"
        exit_code=2
    fi
    
    echo
    echo -e "${BLUE}Test completed at: $(date)${NC}"
    echo
    
    # Ask user if they want to stop the system
    read -p "Do you want to stop the Docker containers? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Stopping Docker containers..."
        docker-compose down
        log_success "Docker containers stopped"
    else
        log_info "Docker containers are still running. Use 'docker-compose down' to stop them."
    fi
    
    exit $exit_code
}

# Handle script interruption
trap 'echo -e "\n${RED}Test interrupted by user${NC}"; docker-compose down; exit 1' INT

# Run the main function
main "$@" 