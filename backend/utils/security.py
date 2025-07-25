import os
import base64

def generate_nonce(length=32):
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8') 