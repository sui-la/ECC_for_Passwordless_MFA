#!/usr/bin/env python3
"""
Script to fix test encoding issues
"""

import os
import re

def fix_encoding_issues(file_path):
    """Fix .encode('utf-8') issues in test files."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Replace .encode('utf-8') with just the variable name
    # This works because serialize_public_key already returns bytes
    content = re.sub(r"\.encode\('utf-8'\)", '', content)
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed encoding issues in {file_path}")

if __name__ == "__main__":
    # Fix database test file
    fix_encoding_issues("tests/test_database.py")
    
    # Fix auth endpoints test file
    fix_encoding_issues("tests/test_auth_endpoints.py")
    
    # Fix security test file
    fix_encoding_issues("tests/test_security.py")
    
    print("All encoding issues fixed!") 