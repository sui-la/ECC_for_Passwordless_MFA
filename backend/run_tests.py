#!/usr/bin/env python3
"""
Test runner script for the ECC Passwordless MFA backend.
"""

import sys
import os
import subprocess
from pathlib import Path

def run_tests():
    """Run all tests with coverage reporting."""
    print("🧪 Running ECC Passwordless MFA Backend Tests")
    print("=" * 50)
    
    # Change to backend directory
    backend_dir = Path(__file__).parent
    os.chdir(backend_dir)
    
    # Install test dependencies if needed
    print("📦 Checking test dependencies...")
    try:
        import pytest
        import pytest_cov
        import pytest_mock
        import factory_boy
    except ImportError:
        print("❌ Test dependencies not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
    
    # Run tests with coverage
    print("🚀 Starting test execution...")
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/",
        "-v",
        "--tb=short",
        "--cov=app",
        "--cov=crypto", 
        "--cov=database",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov",
        "--cov-report=xml",
        "--disable-warnings"
    ]
    
    try:
        result = subprocess.run(cmd, check=True)
        print("\n✅ All tests passed!")
        print("\n📊 Coverage reports generated:")
        print("   - HTML: htmlcov/index.html")
        print("   - XML: coverage.xml")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Tests failed with exit code {e.returncode}")
        return False

def run_security_tests():
    """Run security-focused tests."""
    print("\n🔒 Running Security Tests")
    print("=" * 30)
    
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/test_security.py",
        "-v",
        "--tb=short",
        "-m", "not slow"
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print("✅ Security tests passed!")
        return True
    except subprocess.CalledProcessError:
        print("❌ Security tests failed!")
        return False

def run_unit_tests():
    """Run unit tests only."""
    print("\n🔬 Running Unit Tests")
    print("=" * 25)
    
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/test_crypto.py",
        "tests/test_database.py",
        "-v",
        "--tb=short",
        "-m", "unit"
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print("✅ Unit tests passed!")
        return True
    except subprocess.CalledProcessError:
        print("❌ Unit tests failed!")
        return False

def run_integration_tests():
    """Run integration tests only."""
    print("\n🔗 Running Integration Tests")
    print("=" * 30)
    
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/test_auth_endpoints.py",
        "-v",
        "--tb=short",
        "-m", "integration"
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print("✅ Integration tests passed!")
        return True
    except subprocess.CalledProcessError:
        print("❌ Integration tests failed!")
        return False

def main():
    """Main test runner function."""
    if len(sys.argv) > 1:
        test_type = sys.argv[1].lower()
        
        if test_type == "unit":
            success = run_unit_tests()
        elif test_type == "integration":
            success = run_integration_tests()
        elif test_type == "security":
            success = run_security_tests()
        elif test_type == "all":
            success = run_tests()
        else:
            print(f"❌ Unknown test type: {test_type}")
            print("Available options: unit, integration, security, all")
            return False
    else:
        # Default: run all tests
        success = run_tests()
    
    if success:
        print("\n🎉 Test execution completed successfully!")
        return True
    else:
        print("\n💥 Test execution failed!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 