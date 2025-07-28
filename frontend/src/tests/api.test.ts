import {
  register,
  getChallenge,
  verify,
  sendECDHPublicKey,
  sendSecureData,
  getDevices,
  addDevice,
  removeDevice,
  getDevicePublicKey,
  initiateRecovery,
  verifyRecoveryToken,
  completeRecovery,
  generateBackupKey,
} from '../services/api';

// Mock fetch
global.fetch = jest.fn();

describe('API Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      const mockResponse = {
        message: 'User registered successfully',
        user_id: 'user-123',
        device_id: 'device-123',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await register('test@example.com', 'public-key-pem', 'Test Device');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'test@example.com',
          public_key_pem: 'public-key-pem',
          device_name: 'Test Device',
        }),
      });
      expect(result).toEqual(mockResponse);
    });

    it('should handle registration errors', async () => {
      const mockError = { error: 'Email already exists' };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        json: async () => mockError,
      });

      await expect(register('test@example.com', 'public-key-pem', 'Test Device'))
        .rejects.toThrow('Email already exists');
    });
  });

  describe('getChallenge', () => {
    it('should request authentication challenge successfully', async () => {
      const mockResponse = { nonce: 'challenge-nonce-123' };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await getChallenge('test@example.com');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/auth/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' }),
      });
      expect(result).toEqual(mockResponse);
    });

    it('should handle challenge request errors', async () => {
      const mockError = { error: 'User not found' };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        json: async () => mockError,
      });

      await expect(getChallenge('test@example.com'))
        .rejects.toThrow('User not found');
    });
  });

  describe('verify', () => {
    it('should verify authentication successfully', async () => {
      const mockResponse = {
        token: 'jwt-token-123',
        server_ecdh_public_key: 'server-public-key',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await verify('test@example.com', 'signature-123');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'test@example.com',
          signature: 'signature-123',
        }),
      });
      expect(result).toEqual(mockResponse);
    });

    it('should handle verification errors', async () => {
      const mockError = { error: 'Invalid signature' };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        json: async () => mockError,
      });

      await expect(verify('test@example.com', 'invalid-signature'))
        .rejects.toThrow('Invalid signature');
    });
  });

  describe('sendECDHPublicKey', () => {
    it('should send ECDH public key successfully', async () => {
      const mockResponse = { message: 'Shared secret established.' };
      localStorage.setItem('jwt', 'test-token');

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await sendECDHPublicKey('client-public-key');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/session/ecdh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-token',
        },
        body: JSON.stringify({ client_ecdh_public_key: 'client-public-key' }),
      });
      expect(result).toEqual(mockResponse);
    });

    it('should handle missing JWT token', async () => {
      await expect(sendECDHPublicKey('client-public-key'))
        .rejects.toThrow('No authentication token found');
    });
  });

  describe('sendSecureData', () => {
    it('should send secure data successfully', async () => {
      const mockResponse = {
        ciphertext: 'encrypted-response',
        iv: 'response-iv',
      };
      localStorage.setItem('jwt', 'test-token');

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await sendSecureData('encrypted-data', 'data-iv');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/session/secure-data', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-token',
        },
        body: JSON.stringify({
          ciphertext: 'encrypted-data',
          iv: 'data-iv',
        }),
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('getDevices', () => {
    it('should get user devices successfully', async () => {
      const mockResponse = {
        devices: [
          {
            device_id: 'device-1',
            device_name: 'Test Device',
            created_at: '2023-01-01T00:00:00Z',
            last_used: '2023-01-01T12:00:00Z',
            is_active: true,
          },
        ],
      };
      localStorage.setItem('jwt', 'test-token');

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await getDevices();

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/devices', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-token',
        },
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('addDevice', () => {
    it('should add device successfully', async () => {
      const mockResponse = {
        message: 'Device added successfully',
        device_id: 'new-device-123',
        device_name: 'New Device',
      };
      localStorage.setItem('jwt', 'test-token');

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await addDevice('public-key-pem', 'New Device');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/devices', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-token',
        },
        body: JSON.stringify({
          public_key_pem: 'public-key-pem',
          device_name: 'New Device',
        }),
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('removeDevice', () => {
    it('should remove device successfully', async () => {
      const mockResponse = { message: 'Device removed successfully' };
      localStorage.setItem('jwt', 'test-token');

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await removeDevice('device-123');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/devices/device-123', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-token',
        },
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('getDevicePublicKey', () => {
    it('should get device public key successfully', async () => {
      const mockResponse = {
        device_id: 'device-123',
        device_name: 'Test Device',
        public_key_pem: 'public-key-pem',
      };
      localStorage.setItem('jwt', 'test-token');

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await getDevicePublicKey('device-123');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/devices/device-123/public-key', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-token',
        },
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('initiateRecovery', () => {
    it('should initiate recovery successfully', async () => {
      const mockResponse = { message: 'Recovery email sent successfully.' };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await initiateRecovery('test@example.com');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/recovery/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' }),
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('verifyRecoveryToken', () => {
    it('should verify recovery token successfully', async () => {
      const mockResponse = { email: 'test@example.com' };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await verifyRecoveryToken('recovery-token-123');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/recovery/verify-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recovery_token: 'recovery-token-123' }),
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('completeRecovery', () => {
    it('should complete recovery successfully', async () => {
      const mockResponse = {
        message: 'Recovery completed successfully',
        device_id: 'recovery-device-123',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await completeRecovery('recovery-token-123', 'public-key-pem', 'Recovery Device');

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/recovery/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recovery_token: 'recovery-token-123',
          public_key_pem: 'public-key-pem',
          device_name: 'Recovery Device',
        }),
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('generateBackupKey', () => {
    it('should generate backup key successfully', async () => {
      const mockResponse = {
        public_key_pem: 'backup-public-key',
        private_key_pem: 'backup-private-key',
      };
      localStorage.setItem('jwt', 'test-token');

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await generateBackupKey();

      expect(fetch).toHaveBeenCalledWith('http://localhost:5000/backup/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-token',
        },
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('Error handling', () => {
    it('should handle network errors', async () => {
      (fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

      await expect(getChallenge('test@example.com'))
        .rejects.toThrow('Network error');
    });

    it('should handle JSON parsing errors', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        json: async () => {
          throw new Error('Invalid JSON');
        },
      });

      await expect(getChallenge('test@example.com'))
        .rejects.toThrow('Invalid JSON');
    });
  });
}); 