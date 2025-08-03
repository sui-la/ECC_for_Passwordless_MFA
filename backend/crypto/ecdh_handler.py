from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64
import os
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)

def derive_shared_secret(private_key, peer_public_key) -> bytes:
    """
    Derive shared secret using ECDH key exchange.
    
    Args:
        private_key: Local private key
        peer_public_key: Peer's public key
        
    Returns:
        bytes: Raw shared secret
    """
    try:
        return private_key.exchange(ec.ECDH(), peer_public_key)
    except Exception as e:
        logger.error(f"ECDH key exchange failed: {e}")
        raise ValueError("Failed to derive shared secret")

def derive_session_keys(shared_secret: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """
    Derive session keys from shared secret using HKDF.
    
    Args:
        shared_secret: Raw shared secret from ECDH
        salt: Optional salt for key derivation
        
    Returns:
        Tuple[bytes, bytes, bytes]: (encryption_key, mac_key, iv)
    """
    if salt is None:
        salt = os.urandom(32)
    
    # Use HKDF to derive multiple keys
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=96,  # 32 bytes each for encryption, MAC, and IV
        salt=salt,
        info=b'ecc-mfa-session-keys',
        backend=default_backend()
    )
    
    derived_keys = hkdf.derive(shared_secret)
    
    # Split into individual keys
    encryption_key = derived_keys[:32]
    mac_key = derived_keys[32:64]
    iv = derived_keys[64:96]
    
    return encryption_key, mac_key, iv

def generate_ephemeral_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generate ephemeral ECDH key pair for perfect forward secrecy.
    
    Returns:
        Tuple: (private_key, public_key)
    """
    try:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        logger.error(f"Failed to generate ephemeral keypair: {e}")
        raise ValueError("Failed to generate ephemeral keys")

def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """
    Serialize public key to PEM format.
    
    Args:
        public_key: Public key to serialize
        
    Returns:
        str: PEM encoded public key
    """
    try:
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to serialize public key: {e}")
        raise ValueError("Failed to serialize public key")

def deserialize_public_key(pem_data: str) -> ec.EllipticCurvePublicKey:
    """
    Deserialize public key from PEM format.
    
    Args:
        pem_data: PEM encoded public key
        
    Returns:
        EllipticCurvePublicKey: Deserialized public key
    """
    try:
        if isinstance(pem_data, str):
            pem_data = pem_data.encode('utf-8')
        
        public_key = serialization.load_pem_public_key(pem_data, default_backend())
        
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Invalid key type")
            
        return public_key
    except Exception as e:
        logger.error(f"Failed to deserialize public key: {e}")
        raise ValueError("Invalid public key format")

def validate_key_compatibility(private_key: ec.EllipticCurvePrivateKey, 
                             public_key: ec.EllipticCurvePublicKey) -> bool:
    """
    Validate that private and public keys are compatible for ECDH.
    
    Args:
        private_key: Local private key
        public_key: Peer's public key
        
    Returns:
        bool: True if keys are compatible
    """
    try:
        # Check if both keys use the same curve
        private_curve = private_key.curve
        public_curve = public_key.curve
        
        if private_curve.name != public_curve.name:
            logger.warning(f"Key curve mismatch: {private_curve.name} vs {public_curve.name}")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Key validation failed: {e}")
        return False

def create_session_context(session_id: str, shared_secret: bytes) -> dict:
    """
    Create a session context with derived keys and metadata.
    
    Args:
        session_id: Unique session identifier
        shared_secret: Raw shared secret
        
    Returns:
        dict: Session context with keys and metadata
    """
    try:
        encryption_key, mac_key, iv = derive_session_keys(shared_secret)
        
        return {
            'session_id': session_id,
            'encryption_key': base64.b64encode(encryption_key).decode('utf-8'),
            'mac_key': base64.b64encode(mac_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'created_at': int(os.urandom(4).hex(), 16),  # Simple timestamp
            'key_derivation_salt': base64.b64encode(os.urandom(32)).decode('utf-8')
        }
    except Exception as e:
        logger.error(f"Failed to create session context: {e}")
        raise ValueError("Failed to create session context") 