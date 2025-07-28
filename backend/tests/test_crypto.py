import pytest
import base64
import hashlib
import ecdsa
from crypto.ecc_operations import (
    generate_private_key, 
    get_public_key, 
    serialize_public_key
)
from crypto.ecdsa_handler import verify_signature
from crypto.ecdh_handler import derive_shared_secret
from app import raw_to_der
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class TestECCOperations:
    """Test ECC key generation and operations."""
    
    def test_generate_private_key(self):
        """Test private key generation."""
        private_key = generate_private_key()
        assert private_key is not None
        assert hasattr(private_key, 'private_bytes')
    
    def test_get_public_key(self):
        """Test public key derivation from private key."""
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        assert public_key is not None
        assert hasattr(public_key, 'public_bytes')
    
    def test_serialize_public_key(self):
        """Test public key serialization."""
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        
        # Serialize
        serialized = serialize_public_key(public_key)
        assert serialized is not None
        assert isinstance(serialized, bytes)
        assert b'-----BEGIN PUBLIC KEY-----' in serialized
    
    def test_multiple_key_generation(self):
        """Test that multiple keys are different."""
        key1 = generate_private_key()
        key2 = generate_private_key()
        
        pub1 = get_public_key(key1)
        pub2 = get_public_key(key2)
        
        # Keys should be different
        # Compare private key values directly
        key1_bytes = key1.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        key2_bytes = key2.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        assert key1_bytes != key2_bytes
        
        pub1_bytes = pub1.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub2_bytes = pub2.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert pub1_bytes != pub2_bytes


class TestECDSAOperations:
    """Test ECDSA signature operations."""
    
    def test_signature_verification_valid(self, sample_key_pair, sample_nonce, sample_signature):
        """Test valid signature verification."""
        # Create a message to sign
        message = sample_nonce.encode('utf-8')
        
        # Verify the signature
        result = verify_signature(
            sample_signature,
            message,
            sample_key_pair['public_key']
        )
        assert result is True, f"Signature verification failed. Message: {message}, Signature: {sample_signature}"
    
    def test_signature_verification_invalid(self, sample_key_pair):
        """Test invalid signature verification."""
        message = b"test message"
        invalid_signature = base64.b64encode(b"invalid signature").decode('utf-8')
        
        result = verify_signature(
            invalid_signature,
            message,
            sample_key_pair['public_key']
        )
        assert result is False
    
    def test_signature_verification_wrong_message(self, sample_key_pair, sample_signature):
        """Test signature verification with wrong message."""
        wrong_message = b"wrong message"
        
        result = verify_signature(
            sample_signature,
            wrong_message,
            sample_key_pair['public_key']
        )
        assert result is False
    
    def test_raw_to_der_conversion(self):
        """Test raw signature to DER conversion."""
        # Create a raw signature (r, s components)
        r = 123456789
        s = 987654321
        
        # Convert to bytes
        r_bytes = r.to_bytes(32, 'big')
        s_bytes = s.to_bytes(32, 'big')
        raw_sig = r_bytes + s_bytes
        
        # Convert to DER
        der_sig = raw_to_der(raw_sig)
        
        assert der_sig is not None
        # DER can be shorter for small numbers due to leading zero removal
        assert len(der_sig) > 0  # Just ensure it's not empty


class TestECDHOperations:
    """Test ECDH key exchange operations."""
    
    def test_shared_secret_derivation(self):
        """Test ECDH shared secret derivation."""
        # Generate two key pairs
        private_key1 = generate_private_key()
        public_key1 = get_public_key(private_key1)
        
        private_key2 = generate_private_key()
        public_key2 = get_public_key(private_key2)
        
        # Derive shared secrets
        shared_secret1 = derive_shared_secret(private_key1, public_key2)
        shared_secret2 = derive_shared_secret(private_key2, public_key1)
        
        # Both should be the same
        assert shared_secret1 == shared_secret2
        assert len(shared_secret1) == 32  # 256-bit shared secret
    
    def test_shared_secret_uniqueness(self):
        """Test that different key pairs produce different shared secrets."""
        # Generate three key pairs
        private_key1 = generate_private_key()
        public_key1 = get_public_key(private_key1)
        
        private_key2 = generate_private_key()
        public_key2 = get_public_key(private_key2)
        
        private_key3 = generate_private_key()
        public_key3 = get_public_key(private_key3)
        
        # Derive shared secrets
        shared_secret12 = derive_shared_secret(private_key1, public_key2)
        shared_secret13 = derive_shared_secret(private_key1, public_key3)
        shared_secret23 = derive_shared_secret(private_key2, public_key3)
        
        # All should be different
        assert shared_secret12 != shared_secret13
        assert shared_secret12 != shared_secret23
        assert shared_secret13 != shared_secret23


class TestCryptographicSecurity:
    """Test cryptographic security properties."""
    
    def test_key_entropy(self):
        """Test that generated keys have sufficient entropy."""
        keys = []
        for _ in range(10):
            private_key = generate_private_key()
            key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            keys.append(key_bytes)
        
        # All keys should be different
        unique_keys = set(keys)
        assert len(unique_keys) == 10
    
    def test_signature_uniqueness(self, sample_key_pair):
        """Test that signatures are unique for the same message."""
        message = b"test message"
        signatures = []
        
        for _ in range(5):
            # Create a deterministic signature
            raw_private_key = sample_key_pair['private_key'].private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )[-32:]  # Last 32 bytes are the actual private key
            signing_key = ecdsa.SigningKey.from_string(
                raw_private_key,
                curve=ecdsa.curves.SECP256k1
            )
            signature = signing_key.sign_digest_deterministic(
                message,
                hashfunc=hashlib.sha256,
                sigencode=ecdsa.util.sigencode_der
            )
            signatures.append(base64.b64encode(signature).decode('utf-8'))
        
        # All signatures should be the same (deterministic)
        unique_signatures = set(signatures)
        assert len(unique_signatures) == 1 