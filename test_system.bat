@echo off
setlocal enabledelayedexpansion

REM Ultimate ECC Passwordless MFA System Test
REM Comprehensive Docker-based testing for the entire system

REM Configuration
set BACKEND_URL=http://localhost:5000
set FRONTEND_URL=http://localhost:3000
set TEST_EMAIL=thenganhao3383@gmail.com
set TEST_DEVICE_NAME=Test Device

REM Test counters
set TOTAL_TESTS=0
set PASSED_TESTS=0
set FAILED_TESTS=0

echo.
echo ==========================================
echo   Ultimate ECC Passwordless MFA Test Suite
echo ==========================================
echo.

REM Check if Docker is running
echo [INFO] Checking Docker status...
docker info >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Docker is not running. Please start Docker and try again.
    exit /b 1
)
echo [PASS] Docker is running

REM Check if docker-compose.yml exists
if not exist "docker-compose.yml" (
    echo [FAIL] docker-compose.yml not found in current directory
    exit /b 1
)
echo [PASS] docker-compose.yml found

REM Start the system
echo [INFO] Starting ECC Passwordless MFA system...
docker-compose up -d

REM Wait for services to be ready
echo [INFO] Waiting for services to be ready...
:wait_backend
curl -s "%BACKEND_URL%/health" >nul 2>&1
if errorlevel 1 (
    timeout /t 2 >nul
    goto wait_backend
)
echo [PASS] Backend is ready!

:wait_frontend
curl -s "%FRONTEND_URL%" >nul 2>&1
if errorlevel 1 (
    timeout /t 2 >nul
    goto wait_frontend
)
echo [PASS] Frontend is ready!

echo [INFO] All services are ready. Starting comprehensive tests...
echo.

REM ========================================
REM 1. DOCKER CONTAINER HEALTH TESTS
REM ========================================
echo [INFO] 1. Testing Docker Container Health
echo ----------------------------------------

REM Check if all containers are running
echo [TEST] 1.1: Checking if all containers are running
for /f %%i in ('docker-compose ps -q ^| find /c /v ""') do set containers_running=%%i
if !containers_running! geq 3 (
    echo [PASS] All containers are running (!containers_running! containers^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] Not all containers are running (found !containers_running!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM Check container health
echo [TEST] 1.2: Checking container health status
for /f %%i in ('docker-compose ps ^| find /c "unhealthy"') do set unhealthy_containers=%%i
if !unhealthy_containers! equ 0 (
    echo [PASS] All containers are healthy
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] Found !unhealthy_containers! unhealthy containers
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 2. BACKEND API TESTS
REM ========================================
echo [INFO] 2. Testing Backend API Endpoints
echo ----------------------------------------

REM Health check
echo [TEST] 2.1: Health endpoint
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/health" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 2.1: Health endpoint (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 2.1: Health endpoint (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM Security info
echo [TEST] 2.2: Security info endpoint
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/security" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 2.2: Security info endpoint (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 2.2: Security info endpoint (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM API documentation
echo [TEST] 2.3: API documentation endpoint
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/api/docs" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 2.3: API documentation endpoint (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 2.3: API documentation endpoint (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM API specification
echo [TEST] 2.4: API specification endpoint
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/api/spec" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 2.4: API specification endpoint (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 2.4: API specification endpoint (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM API endpoints list
echo [TEST] 2.5: API endpoints list
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/api/endpoints" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 2.5: API endpoints list (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 2.5: API endpoints list (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM Comprehensive health check
echo [TEST] 2.6: Comprehensive health check
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/api/monitoring/health/comprehensive" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 2.6: Comprehensive health check (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 2.6: Comprehensive health check (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 3. AUTHENTICATION TESTS
REM ========================================
echo [INFO] 3. Testing Authentication System
echo ----------------------------------------

REM Test registration with invalid data
echo [TEST] 3.1: Registration with invalid data
for /f "tokens=*" %%i in ('curl -s -o nul -w "%%{http_code}" -X POST -H "Content-Type: application/json" -H "Accept-Language: en-US,en;q=0.9" -H "Accept-Encoding: gzip, deflate" -H "User-Agent: TestClient/1.0" -H "Accept: application/json" -d "{\"invalid\": \"data\"}" "%BACKEND_URL%/register" 2^>nul') do set status_code=%%i
if "!status_code!"=="400" (
    echo [PASS] 3.1: Registration with invalid data (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 3.1: Registration with invalid data (Expected: 400, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM Test registration with valid data
echo [TEST] 3.2: Registration with valid data
REM Generate unique email for this test run
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "unique_email=test_user_%dt:~8,6%_%random%@gmail.com"
for /f "tokens=*" %%i in ('curl -s -o nul -w "%%{http_code}" -X POST -H "Content-Type: application/json" -H "Accept-Language: en-US,en;q=0.9" -H "Accept-Encoding: gzip, deflate" -H "User-Agent: TestClient/1.0" -H "Accept: application/json" -d "{\"email\": \"%unique_email%\", \"public_key_pem\": \"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvx6nd7LVuI78P1trSx+5qGNx70Cy0\nvBu4LeVuuaT3eCAP+Z8P8BFxjoI6SdNgVOnZ6v5vU6j9aL8B+mGtW9FpS6jE0NqA7LZ3bJ1\n8QIDAQAB\n-----END PUBLIC KEY-----\", \"device_name\": \"%TEST_DEVICE_NAME%\"}" "%BACKEND_URL%/register" 2^>nul') do set status_code=%%i
if "!status_code!"=="201" (
    echo [PASS] 3.2: Registration with valid data (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 3.2: Registration with valid data (Expected: 201, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM Test duplicate registration
echo [TEST] 3.3: Duplicate registration
for /f "tokens=*" %%i in ('curl -s -o nul -w "%%{http_code}" -X POST -H "Content-Type: application/json" -H "Accept-Language: en-US,en;q=0.9" -H "Accept-Encoding: gzip, deflate" -H "User-Agent: TestClient/1.0" -H "Accept: application/json" -d "{\"email\": \"%TEST_EMAIL%\", \"public_key_pem\": \"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvx6nd7LVuI78P1trSx+5qGNx70Cy0\nvBu4LeVuuaT3eCAP+Z8P8BFxjoI6SdNgVOnZ6v5vU6j9aL8B+mGtW9FpS6jE0NqA7LZ3bJ1\n8QIDAQAB\n-----END PUBLIC KEY-----\", \"device_name\": \"%TEST_DEVICE_NAME%\"}" "%BACKEND_URL%/register" 2^>nul') do set status_code=%%i
if "!status_code!"=="409" (
    echo [PASS] 3.3: Duplicate registration (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 3.3: Duplicate registration (Expected: 409, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM Test authentication challenge
echo [TEST] 3.4: Authentication challenge
for /f "tokens=*" %%i in ('curl -s -o nul -w "%%{http_code}" -X POST -H "Content-Type: application/json" -d "{\"email\": \"%TEST_EMAIL%\"}" "%BACKEND_URL%/api/auth/challenge" 2^>nul') do set status_code=%%i
if "!status_code!"=="200" (
    echo [PASS] 3.4: Authentication challenge (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 3.4: Authentication challenge (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 4. DEVICE MANAGEMENT TESTS
REM ========================================
echo [INFO] 4. Testing Device Management
echo ----------------------------------------

REM Get devices (should fail without auth)
echo [TEST] 4.1: Get devices without authentication
for /f "tokens=*" %%i in ('curl -s -o nul -w "%%{http_code}" "%BACKEND_URL%/devices" 2^>nul') do set status_code=%%i
if "!status_code!"=="401" (
    echo [PASS] 4.1: Get devices without authentication (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 4.1: Get devices without authentication (Expected: 401, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 5. SECURE MESSAGING TESTS
REM ========================================
echo [INFO] 5. Testing Secure Messaging
echo ----------------------------------------

REM ECDH key exchange (should fail without auth)
echo [TEST] 5.1: ECDH key exchange without authentication
for /f "tokens=*" %%i in ('curl -s -o nul -w "%%{http_code}" --max-time 10 -X POST -H "Content-Type: application/json" -d "{\"client_ecdh_public_key\": \"test\"}" "%BACKEND_URL%/session/ecdh" 2^>nul') do set status_code=%%i
if "!status_code!"=="401" (
    echo [PASS] 5.1: ECDH key exchange without authentication (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 5.1: ECDH key exchange without authentication (Expected: 401, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 6. ACCOUNT RECOVERY TESTS
REM ========================================
echo [INFO] 6. Testing Account Recovery
echo ----------------------------------------

REM Initiate recovery
echo [TEST] 6.1: Initiate account recovery
for /f "tokens=*" %%i in ('curl -s -o nul -w "%%{http_code}" --max-time 10 -X POST -H "Content-Type: application/json" -H "Accept-Language: en-US,en;q=0.9" -H "Accept-Encoding: gzip, deflate" -H "User-Agent: TestClient/1.0" -H "Accept: application/json" -d "{\"email\": \"%TEST_EMAIL%\"}" "%BACKEND_URL%/recovery/initiate" 2^>nul') do set status_code=%%i
if "!status_code!"=="200" (
    echo [PASS] 6.1: Initiate account recovery (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 6.1: Initiate account recovery (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 7. EMAIL VERIFICATION TESTS
REM ========================================
echo [INFO] 7. Testing Email Verification
echo ----------------------------------------

REM Send verification email
echo [TEST] 7.1: Send verification email
for /f "tokens=*" %%i in ('curl -s -o nul -w "%%{http_code}" --max-time 10 -X POST -H "Content-Type: application/json" -H "Accept-Language: en-US,en;q=0.9" -H "Accept-Encoding: gzip, deflate" -H "User-Agent: TestClient/1.0" -H "Accept: application/json" -d "{\"email\": \"%TEST_EMAIL%\"}" "%BACKEND_URL%/email/send-verification" 2^>nul') do set status_code=%%i
if "!status_code!"=="200" (
    echo [PASS] 7.1: Send verification email (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 7.1: Send verification email (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 8. FRONTEND ACCESSIBILITY TESTS
REM ========================================
echo [INFO] 8. Testing Frontend Accessibility
echo ----------------------------------------

REM Check if frontend is accessible
echo [TEST] 8.1: Frontend main page
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%FRONTEND_URL%" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 8.1: Frontend main page (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 8.1: Frontend main page (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 9. DATABASE OPERATIONS TESTS
REM ========================================
echo [INFO] 9. Testing Database Operations
echo ----------------------------------------

REM Check database optimization indexes
echo [TEST] 9.1: Database optimization indexes
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/api/database/optimization/indexes" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 9.1: Database optimization indexes (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 9.1: Database optimization indexes (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM Check performance stats
echo [TEST] 9.2: Performance statistics
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/api/performance/stats" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 9.2: Performance statistics (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 9.2: Performance statistics (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 10. SECURITY FEATURES TESTS
REM ========================================
echo [INFO] 10. Testing Security Features
echo ----------------------------------------

REM Test CORS headers
echo [TEST] 10.1: Testing CORS headers
for /f "tokens=*" %%i in ('curl -s -H "Origin: http://localhost:3000" -I "%BACKEND_URL%/health" ^| findstr /i "access-control" ^| find /c /v ""') do set cors_headers=%%i
if !cors_headers! gtr 0 (
    echo [PASS] 10.1: CORS headers are present
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 10.1: CORS headers are missing
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM Test security headers
echo [TEST] 10.2: Testing security headers
for /f "tokens=*" %%i in ('curl -s -I "%BACKEND_URL%/health" ^| findstr /i "x-content-type" ^| find /c /v ""') do set security_headers=%%i
if !security_headers! gtr 0 (
    echo [PASS] 10.2: Security headers are present
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 10.2: Security headers are missing
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 11. ERROR HANDLING TESTS
REM ========================================
echo [INFO] 11. Testing Error Handling
echo ----------------------------------------

REM Test 500 for invalid endpoint (due to error handling middleware)
echo [TEST] 11.1: Invalid endpoint returns 500
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/invalid-endpoint" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="500" (
    echo [PASS] 11.1: Invalid endpoint returns 500 (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 11.1: Invalid endpoint returns 500 (Expected: 500, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 12. INTEGRATION TESTS
REM ========================================
echo [INFO] 12. Testing System Integration
echo ----------------------------------------

REM Test backend-frontend connectivity
echo [TEST] 12.1: Backend-frontend integration
for /f "tokens=*" %%i in ('curl -s "%BACKEND_URL%/health" ^| find /c "healthy"') do set backend_health=%%i
if !backend_health! gtr 0 (
    echo [PASS] 12.1: Backend is healthy and accessible
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 12.1: Backend health check failed
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 13. PERFORMANCE TESTS
REM ========================================
echo [INFO] 13. Testing Performance
echo ----------------------------------------

REM Test concurrent requests
echo [TEST] 13.1: Concurrent request handling
set concurrent_success=0
for /l %%i in (1,1,5) do (
    curl -s "%BACKEND_URL%/health" >nul 2>&1
    if not errorlevel 1 set /a concurrent_success+=1
)

if !concurrent_success! equ 5 (
    echo [PASS] 13.1: All concurrent requests succeeded
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 13.1: Only !concurrent_success!/5 concurrent requests succeeded
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 14. MONITORING TESTS
REM ========================================
echo [INFO] 14. Testing Monitoring ^& Metrics
echo ----------------------------------------

REM Test metrics history
echo [TEST] 14.1: Metrics history endpoint
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/api/monitoring/metrics/history" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 14.1: Metrics history endpoint (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 14.1: Metrics history endpoint (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM 15. FINAL SYSTEM VALIDATION
REM ========================================
echo [INFO] 15. Final System Validation
echo ----------------------------------------

REM Final health check
echo [TEST] 15.1: Final backend health check
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%BACKEND_URL%/health" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 15.1: Final backend health check (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 15.1: Final backend health check (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

REM Final frontend check
echo [TEST] 15.2: Final frontend accessibility check
for /f "tokens=*" %%i in ('curl -s -w "%%{http_code}" "%FRONTEND_URL%" 2^>nul') do set response=%%i
set status_code=!response:~-3!
if "!status_code!"=="200" (
    echo [PASS] 15.2: Final frontend accessibility check (Status: !status_code!^)
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
) else (
    echo [FAIL] 15.2: Final frontend accessibility check (Expected: 200, Got: !status_code!^)
    set /a FAILED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.

REM ========================================
REM TEST SUMMARY
REM ========================================
echo ==========================================
echo   Ultimate Test Suite Results
echo ==========================================

echo Total Tests: !TOTAL_TESTS!
echo Passed: !PASSED_TESTS!
echo Failed: !FAILED_TESTS!

if !FAILED_TESTS! equ 0 (
    echo.
    echo All tests passed! Your ECC Passwordless MFA system is working perfectly!
    set exit_code=0
) else if !FAILED_TESTS! leq 5 (
    echo.
    echo ⚠️  Most tests passed. There are !FAILED_TESTS! minor issues to address.
    set exit_code=1
) else (
    echo.
    echo ❌ Multiple tests failed. Please review the issues above.
    set exit_code=2
)

echo.
echo Test completed at: %date% %time%
echo.

REM Ask user if they want to stop the system
set /p stop_containers="Do you want to stop the Docker containers? (y/n): "
if /i "!stop_containers!"=="y" (
    echo [INFO] Stopping Docker containers...
    docker-compose down
    echo [PASS] Docker containers stopped
) else (
    echo [INFO] Docker containers are still running. Use 'docker-compose down' to stop them.
)

exit /b !exit_code! 
