from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key) 