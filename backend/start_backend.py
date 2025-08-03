#!/usr/bin/env python3
"""Simple startup script for the ECC MFA backend with error handling."""

import sys
import os
import traceback

def main():
    """Start the backend with comprehensive error handling."""
    try:
        print("🚀 Starting ECC Passwordless MFA Backend...")
        
        # Add current directory to Python path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Import and start the app
        from app import app
        
        print("✅ Backend initialized successfully!")
        print("🌐 Starting server on http://0.0.0.0:5000")
        print("📊 Health check available at http://localhost:5000/health")
        
        # Start the Flask app
        app.run(host='0.0.0.0', port=5000, debug=True)
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure all dependencies are installed:")
        print("   pip install -r requirements.txt")
        traceback.print_exc()
        sys.exit(1)
        
    except Exception as e:
        print(f"❌ Startup error: {e}")
        print("🔍 Full error details:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 