"""
Legacy app.py file for backward compatibility.
This file maintains the old import structure while using the new blueprint-based architecture.
"""

from app_factory import create_app

# Create the app instance
app = create_app()

# Export the app for backward compatibility
__all__ = ['app']
