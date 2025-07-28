import {
  generateKeyPair,
  exportPublicKey,
  signMessage,
  generateECDHKeyPair,
  exportECDHPublicKey,
  importECDHPublicKey,
  deriveSharedSecret,
  importAesKeyFromSharedSecret,
  aesGcmEncrypt,
  aesGcmDecrypt,
} from '../services/crypto';
import { mockCrypto, mockCryptoSubtle } from '../setupTests';

describe('Crypto Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('generateKeyPair', () => {
    it('should generate ECDSA key pair', async () => {
      const mockPrivateKey = { type: 'private' };
      const mockPublicKey = { type: 'public' };

      mockCrypto.subtle.generateKey.mockResolvedValue({
        privateKey: mockPrivateKey,
        publicKey: mockPublicKey,
      });

      const result = await generateKeyPair();

      expect(mockCrypto.subtle.generateKey).toHaveBeenCalledWith(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        true,
        ['sign', 'verify']
      );
      expect(result.privateKey).toBe(mockPrivateKey);
      expect(result.publicKey).toBe(mockPublicKey);
    });

    it('should handle generation errors', async () => {
      mockCrypto.subtle.generateKey.mockRejectedValue(new Error('Generation failed'));

      await expect(generateKeyPair()).rejects.toThrow('Generation failed');
    });
  });

  describe('exportPublicKey', () => {
    it('should export public key to PEM format', async () => {
      const mockPublicKey = { type: 'public' };
      const mockExportedKey = new Uint8Array([1, 2, 3, 4]);

      mockCrypto.subtle.exportKey.mockResolvedValue(mockExportedKey);

      const result = await exportPublicKey(mockPublicKey);

      expect(mockCrypto.subtle.exportKey).toHaveBeenCalledWith(
        'spki',
        mockPublicKey
      );
      expect(result).toContain('-----BEGIN PUBLIC KEY-----');
      expect(result).toContain('-----END PUBLIC KEY-----');
    });

    it('should handle export errors', async () => {
      const mockPublicKey = { type: 'public' };
      mockCrypto.subtle.exportKey.mockRejectedValue(new Error('Export failed'));

      await expect(exportPublicKey(mockPublicKey)).rejects.toThrow('Export failed');
    });
  });

  describe('signMessage', () => {
    it('should sign a string message', async () => {
      const mockPrivateKey = { type: 'private' };
      const mockSignature = new Uint8Array([1, 2, 3, 4]);
      const message = 'test message';

      mockCrypto.subtle.sign.mockResolvedValue(mockSignature);

      const result = await signMessage(mockPrivateKey, message);

      expect(mockCrypto.subtle.sign).toHaveBeenCalledWith(
        {
          name: 'ECDSA',
          hash: 'SHA-256',
        },
        mockPrivateKey,
        expect.any(Uint8Array)
      );
      expect(result).toBe('AQIDBA=='); // base64 encoded signature
    });

    it('should sign an ArrayBuffer message', async () => {
      const mockPrivateKey = { type: 'private' };
      const mockSignature = new Uint8Array([1, 2, 3, 4]);
      const message = new ArrayBuffer(4);

      mockCrypto.subtle.sign.mockResolvedValue(mockSignature);

      const result = await signMessage(mockPrivateKey, message);

      expect(mockCrypto.subtle.sign).toHaveBeenCalledWith(
        {
          name: 'ECDSA',
          hash: 'SHA-256',
        },
        mockPrivateKey,
        expect.any(Uint8Array)
      );
      expect(result).toBe('AQIDBA==');
    });

    it('should handle signing errors', async () => {
      const mockPrivateKey = { type: 'private' };
      const message = 'test message';

      mockCrypto.subtle.sign.mockRejectedValue(new Error('Signing failed'));

      await expect(signMessage(mockPrivateKey, message)).rejects.toThrow('Signing failed');
    });
  });

  describe('generateECDHKeyPair', () => {
    it('should generate ECDH key pair', async () => {
      const mockPrivateKey = { type: 'private' };
      const mockPublicKey = { type: 'public' };

      mockCrypto.subtle.generateKey.mockResolvedValue({
        privateKey: mockPrivateKey,
        publicKey: mockPublicKey,
      });

      const result = await generateECDHKeyPair();

      expect(mockCrypto.subtle.generateKey).toHaveBeenCalledWith(
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        true,
        ['deriveKey', 'deriveBits']
      );
      expect(result.privateKey).toBe(mockPrivateKey);
      expect(result.publicKey).toBe(mockPublicKey);
    });
  });

  describe('exportECDHPublicKey', () => {
    it('should export ECDH public key to PEM format', async () => {
      const mockPublicKey = { type: 'public' };
      const mockExportedKey = new Uint8Array([1, 2, 3, 4]);

      mockCrypto.subtle.exportKey.mockResolvedValue(mockExportedKey);

      const result = await exportECDHPublicKey(mockPublicKey);

      expect(mockCrypto.subtle.exportKey).toHaveBeenCalledWith(
        'spki',
        mockPublicKey
      );
      expect(result).toContain('-----BEGIN PUBLIC KEY-----');
      expect(result).toContain('-----END PUBLIC KEY-----');
    });
  });

  describe('importECDHPublicKey', () => {
    it('should import ECDH public key from PEM format', async () => {
      const mockPublicKey = { type: 'public' };
      const pemKey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----';

      mockCrypto.subtle.importKey.mockResolvedValue(mockPublicKey);

      const result = await importECDHPublicKey(pemKey);

      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'spki',
        expect.any(Uint8Array),
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        true,
        []
      );
      expect(result).toBe(mockPublicKey);
    });
  });

  describe('deriveSharedSecret', () => {
    it('should derive shared secret from ECDH keys', async () => {
      const mockPrivateKey = { type: 'private' };
      const mockPublicKey = { type: 'public' };
      const mockSharedSecret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      mockCrypto.subtle.deriveBits.mockResolvedValue(mockSharedSecret);

      const result = await deriveSharedSecret(mockPrivateKey, mockPublicKey);

      expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledWith(
        {
          name: 'ECDH',
          public: mockPublicKey,
        },
        mockPrivateKey,
        256
      );
      expect(result).toBe(mockSharedSecret);
    });
  });

  describe('importAesKeyFromSharedSecret', () => {
    it('should import AES key from shared secret', async () => {
      const mockAesKey = { type: 'secret' };
      const sharedSecret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      mockCrypto.subtle.importKey.mockResolvedValue(mockAesKey);

      const result = await importAesKeyFromSharedSecret(sharedSecret);

      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'raw',
        sharedSecret,
        'AES-GCM',
        false,
        ['encrypt', 'decrypt']
      );
      expect(result).toBe(mockAesKey);
    });
  });

  describe('aesGcmEncrypt', () => {
    it('should encrypt data with AES-GCM', async () => {
      const mockKey = { type: 'secret' };
      const plaintext = 'test message';
      const mockEncryptedData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      mockCrypto.subtle.encrypt.mockResolvedValue(mockEncryptedData);

      const result = await aesGcmEncrypt(plaintext, mockKey);

      expect(mockCrypto.subtle.encrypt).toHaveBeenCalledWith(
        {
          name: 'AES-GCM',
          iv: expect.any(Uint8Array),
        },
        mockKey,
        expect.any(Uint8Array)
      );
      expect(result).toHaveProperty('ciphertext');
      expect(result).toHaveProperty('iv');
      expect(typeof result.ciphertext).toBe('string');
      expect(typeof result.iv).toBe('string');
    });
  });

  describe('aesGcmDecrypt', () => {
    it('should decrypt data with AES-GCM', async () => {
      const mockKey = { type: 'secret' };
      const ciphertext = 'AQIDBAUGBwg=';
      const iv = 'AQIDBAUGBwg=';
      const mockDecryptedData = new Uint8Array([116, 101, 115, 116]); // "test"

      mockCrypto.subtle.decrypt.mockResolvedValue(mockDecryptedData);

      const result = await aesGcmDecrypt(ciphertext, iv, mockKey);

      expect(mockCrypto.subtle.decrypt).toHaveBeenCalledWith(
        {
          name: 'AES-GCM',
          iv: expect.any(Uint8Array),
        },
        mockKey,
        expect.any(Uint8Array)
      );
      expect(result).toBe('test');
    });
  });
}); 