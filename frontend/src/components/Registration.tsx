import React, { useState, useEffect } from 'react';
import { generateKeyPair, exportPublicKey } from '../services/crypto';
import { savePrivateKey } from '../services/storage';
import { register } from '../services/api';
import { generateDeviceName, detectDeviceInfo, getDetailedDeviceInfo } from '../utils/deviceDetection';

interface RegistrationProps {
  showToast: (message: string, type?: 'success' | 'error' | 'info') => void;
}

const Registration: React.FC<RegistrationProps> = ({ showToast }) => {
  const [email, setEmail] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [detectedDeviceInfo, setDetectedDeviceInfo] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [deviceNameError, setDeviceNameError] = useState<string | null>(null);

  // Auto-detect device name on component mount
  useEffect(() => {
    try {
      const deviceInfo = detectDeviceInfo();
      const autoDeviceName = generateDeviceName(deviceInfo);
      setDeviceName(autoDeviceName);
      setDetectedDeviceInfo(getDetailedDeviceInfo());
    } catch (err) {
      console.warn('Failed to auto-detect device:', err);
      setDeviceName('Unknown Device');
      setDetectedDeviceInfo('Device detection failed');
    }
  }, []);

  const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email) {
      setEmailError('Email is required');
      return false;
    }
    if (!emailRegex.test(email)) {
      setEmailError('Please enter a valid email address');
      return false;
    }
    setEmailError(null);
    return true;
  };

  const validateDeviceName = (name: string): boolean => {
    if (!name.trim()) {
      setDeviceNameError('Device name is required');
      return false;
    }
    if (name.trim().length < 2) {
      setDeviceNameError('Device name must be at least 2 characters');
      return false;
    }
    setDeviceNameError(null);
    return true;
  };

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setEmail(value);
    if (emailError) {
      validateEmail(value);
    }
  };

  const handleDeviceNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setDeviceName(value);
    if (deviceNameError) {
      validateDeviceName(value);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!validateEmail(email) || !validateDeviceName(deviceName)) {
      return;
    }

    setLoading(true);
    try {
      const { privateKey, publicKey } = await generateKeyPair();
      await savePrivateKey(privateKey);
      const publicKeyPem = await exportPublicKey(publicKey);
      await register(email, publicKeyPem, deviceName.trim());
      showToast('Registration successful! You can now authenticate.', 'success');
      setEmail('');
      setDeviceName('');
    } catch (err: any) {
      const errorMessage = err?.message || err || 'Registration failed';
      setError(errorMessage);
      showToast('Registration failed: ' + errorMessage, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="section" aria-labelledby="registration-title">
      <h2 id="registration-title">Register</h2>
      <p className="section-description">
        Create a new account using your email address. A cryptographic key pair will be generated and stored securely on your device.
      </p>
      
      <form onSubmit={handleRegister} noValidate aria-describedby={error ? "registration-error" : undefined}>
        <div className="form-group">
          <label htmlFor="register-email" className="form-label">
            Email Address <span aria-label="required" className="required">*</span>
          </label>
          <input
            id="register-email"
            type="email"
            placeholder="Enter your email address"
            value={email}
            onChange={handleEmailChange}
            onBlur={() => validateEmail(email)}
            required
            aria-describedby={emailError ? "email-error" : undefined}
            disabled={loading}
            autoComplete="email"
          />
          {emailError && (
            <div id="email-error" className="error-message" role="alert" aria-live="polite">
              {emailError}
            </div>
          )}
        </div>

        <div className="form-group">
          <label htmlFor="register-device-name" className="form-label">
            Device Name <span aria-label="required" className="required">*</span>
          </label>
          <input
            id="register-device-name"
            type="text"
            placeholder="e.g., iPhone 14, Work Laptop, Home Desktop"
            value={deviceName}
            onChange={handleDeviceNameChange}
            onBlur={() => validateDeviceName(deviceName)}
            required
            aria-describedby={deviceNameError ? "device-name-error" : "device-info"}
            disabled={loading}
            autoComplete="off"
          />
          {deviceNameError && (
            <div id="device-name-error" className="error-message" role="alert" aria-live="polite">
              {deviceNameError}
            </div>
          )}
          {detectedDeviceInfo && (
            <div id="device-info" className="info-message" style={{ 
              fontSize: '0.85em', 
              color: '#6b7280', 
              marginTop: 4,
              fontStyle: 'italic'
            }}>
              <span aria-hidden="true">🔍</span> Detected: {detectedDeviceInfo}
            </div>
          )}
        </div>

        {error && (
          <div id="registration-error" className="error-message" role="alert" aria-live="polite">
            {error}
          </div>
        )}

        <button 
          type="submit" 
          disabled={loading}
          aria-describedby={loading ? "register-loading" : undefined}
        >
          {loading ? (
            <>
              <span aria-hidden="true">⏳</span>
              <span id="register-loading">Registering...</span>
            </>
          ) : (
            'Register'
          )}
        </button>
      </form>

      <div className="info-box" role="note" aria-label="Registration information">
        <h3>What happens during registration?</h3>
        <ul>
          <li>A unique cryptographic key pair is generated on your device</li>
          <li>Your private key is stored securely in your browser's local storage</li>
          <li>Your public key is sent to our servers for future authentication</li>
          <li>No passwords are ever stored or transmitted</li>
        </ul>
      </div>
    </section>
  );
};

export default Registration; 