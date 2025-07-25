from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

def verify_signature(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def der_to_rs(der_sig: bytes) -> bytes:
    # Parse DER signature to get r and s
    decoded = der.decode(der_sig)
    r, s = decoded[0], decoded[1]
    r_bytes = int(r).to_bytes(32, 'big')
    s_bytes = int(s).to_bytes(32, 'big')
    return r_bytes + s_bytes