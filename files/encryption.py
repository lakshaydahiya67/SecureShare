
import base64
import uuid
import os
from cryptography.fernet import Fernet
from django.conf import settings
from django.utils import timezone
import datetime

def get_encryption_key():
    """Get or generate an encryption key for Fernet"""
    key = getattr(settings, 'ENCRYPTION_KEY', None)
    if key is None:
        # Generate a new key and warn (in production, this should be fixed)
        key = base64.urlsafe_b64encode(os.urandom(32))
        print("WARNING: Using temporary encryption key. Set ENCRYPTION_KEY in settings.")
    
    # Ensure the key is in bytes format for Fernet
    if isinstance(key, str):
        return key.encode()
    return key

def encrypt_url_token(token):
    """Encrypt a URL token for secure file access"""
    key = get_encryption_key()
    f = Fernet(key)
    token_bytes = str(token).encode()
    encrypted_token = f.encrypt(token_bytes)
    # Convert to URL-safe base64 string
    return base64.urlsafe_b64encode(encrypted_token).decode('utf-8')

def decrypt_url_token(encrypted_token):
    """Decrypt a URL token"""
    try:
        key = get_encryption_key()
        f = Fernet(key)
        # Convert from URL-safe base64 string
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_token)
        decrypted_bytes = f.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    except Exception:
        return None

def generate_access_token():
    """Generate a random token for file access"""
    return str(uuid.uuid4())

def get_token_expiry():
    """Return a datetime for token expiry (24 hours from now)"""
    return timezone.now() + datetime.timedelta(hours=24)
