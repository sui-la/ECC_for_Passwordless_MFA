from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

def verify_signature(public_key, signature: bytes, message: bytes) -> bool:
    try:
        # Check if it's a raw signature (64 bytes) or DER signature
        if len(signature) == 64:
            # It's a raw signature (r + s concatenated), convert to DER
            r = int.from_bytes(signature[:32], byteorder='big')
            s = int.from_bytes(signature[32:], byteorder='big')
            der_sig = encode_dss_signature(r, s)
            public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        else:
            # It's already a DER signature, use directly
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def der_to_rs(der_sig: bytes) -> bytes:
    # Parse DER signature to get r and s
    # Note: This function is not currently used and would need proper DER decoding
    # For now, we'll leave it as a placeholder
    raise NotImplementedError("DER to raw signature conversion not implemented")