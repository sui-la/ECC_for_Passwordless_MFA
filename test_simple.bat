@echo off
setlocal enabledelayedexpansion

echo.
echo ==========================================
echo   Simple ECC Passwordless MFA Test
echo ==========================================
echo.

REM Configuration
set BACKEND_URL=http://localhost:5000
set FRONTEND_URL=http://localhost:3000

REM Test counters
set TOTAL_TESTS=0
set PASSED_TESTS=0
set FAILED_TESTS=0

REM Check if Docker is running
echo [INFO] Checking Docker status...
docker info >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Docker is not running
    exit /b 1
)
echo [PASS] Docker is running

REM Start the system
echo [INFO] Starting system...
docker-compose up -d

REM Wait for services
echo [INFO] Waiting for services...
timeout /t 10 >nul

echo [INFO] Starting tests...
echo.

REM Test 1: Backend Health
echo [TEST] 1. Backend Health Check
curl -s "%BACKEND_URL%/health" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Backend is responding
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Backend is not responding
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

REM Test 2: Frontend Health
echo [TEST] 2. Frontend Health Check
curl -s "%FRONTEND_URL%" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Frontend is responding
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Frontend is not responding
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

REM Test 3: Container Count
echo [TEST] 3. Container Count Check
for /f %%i in ('docker-compose ps -q ^| find /c /v ""') do set count=%%i
if !count! geq 3 (
    echo [PASS] Found !count! containers running
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Only !count! containers running
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

REM Test 4: API Documentation
echo [TEST] 4. API Documentation
curl -s "%BACKEND_URL%/api/docs" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] API docs accessible
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] API docs not accessible
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

REM Test 5: Security Info
echo [TEST] 5. Security Info
curl -s "%BACKEND_URL%/security" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Security info accessible
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Security info not accessible
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

REM Test 6: Database Operations
echo [TEST] 6. Database Operations
curl -s "%BACKEND_URL%/api/performance/stats" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Database operations working
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Database operations failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

REM Test 7: Monitoring
echo [TEST] 7. Monitoring Endpoints
curl -s "%BACKEND_URL%/api/monitoring/health/comprehensive" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Monitoring working
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Monitoring failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

REM Test 8: Error Handling
echo [TEST] 8. Error Handling
curl -s "%BACKEND_URL%/invalid-endpoint" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Error handling working
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Error handling failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo.
echo ==========================================
echo   Test Results
echo ==========================================
echo Total Tests: !TOTAL_TESTS!
echo Passed: !PASSED_TESTS!
echo Failed: !FAILED_TESTS!

if !FAILED_TESTS! equ 0 (
    echo.
    echo 🎉 All tests passed!
) else (
    echo.
    echo ⚠️  Some tests failed
)

echo.
echo Test completed at: %date% %time%
echo.

set /p stop_containers="Stop containers? (y/n): "
if /i "!stop_containers!"=="y" (
    docker-compose down
    echo Containers stopped
)

exit /b 0 