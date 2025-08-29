import os
from flask_mail import Message
from mail import mail

def send_notification_email(subject, recipient, body):
    """Send notification email with fallback to mock for testing."""
    
    # Check if we're in testing mode or email is not configured
    if os.environ.get('FLASK_ENV') == 'testing' or not os.environ.get('EMAIL_PASSWORD'):
        # Mock email sending for testing
        print(f"[MOCK EMAIL] To: {recipient}")
        print(f"[MOCK EMAIL] Subject: {subject}")
        print(f"[MOCK EMAIL] Body: {body}")
        print("[MOCK EMAIL] Email would be sent in production environment")
        return True
    
    # Real email sending
    try:
        msg = Message(subject, recipients=[recipient], body=body)
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        # Fallback to mock for development
        if os.environ.get('FLASK_ENV') == 'development':
            print(f"[FALLBACK MOCK EMAIL] To: {recipient}")
            print(f"[FALLBACK MOCK EMAIL] Subject: {subject}")
            print(f"[FALLBACK MOCK EMAIL] Body: {body}")
            return True
        raise e
