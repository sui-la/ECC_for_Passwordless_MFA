import React, { useState, useEffect } from 'react';
import { generateKeyPair, exportPublicKey, signMessage, generateECDHKeyPair, exportECDHPublicKey, importECDHPublicKey, deriveSharedSecret } from '../services/crypto';
import { savePrivateKey, saveSessionSharedSecret } from '../services/storage';
import { register, getChallenge, verify, sendECDHPublicKey } from '../services/api';
import { generateDeviceName, detectDeviceInfo, getDetailedDeviceInfo, getCommonDeviceNames } from '../utils/deviceDetection';
import EmailVerification from './EmailVerification';

interface RegistrationProps {
  showToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
}

const Registration: React.FC<RegistrationProps> = ({ showToast }) => {
  const [email, setEmail] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [detectedDeviceInfo, setDetectedDeviceInfo] = useState<string>('');
  const [deviceOptions, setDeviceOptions] = useState<string[]>([]);
  const [showCustomInput, setShowCustomInput] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [deviceNameError, setDeviceNameError] = useState<string | null>(null);
  const [showEmailVerification, setShowEmailVerification] = useState(false);
  const [pendingRegistration, setPendingRegistration] = useState<{
    email: string;
    deviceName: string;
    privateKey: CryptoKey;
    deviceId?: string;
  } | null>(null);

  // Auto-detect device name and get device options on component mount
  useEffect(() => {
    try {
      const deviceInfo = detectDeviceInfo();
      const autoDeviceName = generateDeviceName(deviceInfo);
      setDeviceName(autoDeviceName);
      setDetectedDeviceInfo(getDetailedDeviceInfo());
      
      // Get common device names for dropdown
      const options = getCommonDeviceNames();
      setDeviceOptions(options);
    } catch (err) {
      console.warn('Failed to auto-detect device:', err);
      setDeviceName('Unknown Device');
      setDetectedDeviceInfo('Device detection failed');
      setDeviceOptions(['Unknown Device', 'Custom Device']);
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

  const handleDeviceNameChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const value = e.target.value;
    setDeviceName(value);
    
    // If "Custom Device" is selected, show custom input
    if (value === 'Custom Device') {
      setShowCustomInput(true);
      setDeviceName('');
    } else {
      setShowCustomInput(false);
    }
    
    if (deviceNameError) {
      validateDeviceName(value);
    }
  };

  const handleEmailVerificationSuccess = async () => {
    if (!pendingRegistration) return;
    
    try {
      // Store the private key with device ID
      if (pendingRegistration.deviceId) {
        await savePrivateKey(pendingRegistration.privateKey, pendingRegistration.deviceId);
      } else {
        await savePrivateKey(pendingRegistration.privateKey);
      }
      
      showToast?.('Registration completed successfully! You can now authenticate.', 'success');
      setShowEmailVerification(false);
      setPendingRegistration(null);
    } catch (err: any) {
      showToast?.('Failed to complete registration: ' + (err?.message || err), 'error');
    }
  };

  const handleEmailVerificationCancel = () => {
    setShowEmailVerification(false);
    setPendingRegistration(null);
    showToast?.('Registration cancelled.', 'info');
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
      const publicKeyPem = await exportPublicKey(publicKey);
      const response = await register(email, publicKeyPem, deviceName.trim());
      console.log('Registration response:', response);
      
      // Store the device ID along with the private key
      if (response.device_id) {
        console.log('Storing device ID:', response.device_id);
        await savePrivateKey(privateKey, response.device_id);
      } else {
        console.log('No device ID in response, storing without device ID');
        await savePrivateKey(privateKey);
      }
      
      // SECURITY FIX: Only handle new user registration
      if (response.message === 'User registered successfully. Please check your email for verification code.') {
        // New user registration - requires email verification
        setPendingRegistration({
          email,
          deviceName: deviceName.trim(),
          privateKey,
          deviceId: response.device_id
        });
        setShowEmailVerification(true);
        setEmail('');
        setDeviceName('');
      } else {
        // Unknown response
        showToast?.('Registration completed. You can now authenticate.', 'success');
        setEmail('');
        setDeviceName('');
      }
    } catch (err: any) {
      // SECURITY FIX: Handle specific error codes with user-friendly messages
      if (err?.response?.data?.code === 'USER_ALREADY_EXISTS') {
        const message = err.response.data.message || 'An account with this email already exists. Please use the authentication flow to sign in.';
        setError(message);
        showToast?.(message, 'error');
      } else if (err?.response?.data?.code === 'EMAIL_NOT_VERIFIED') {
        const message = err.response.data.message || 'Please verify your email address before authenticating.';
        setError(message);
        showToast?.(message, 'error');
      } else {
        const errorMessage = err?.message || err || 'Registration failed';
        setError(errorMessage);
        showToast?.('Registration failed: ' + errorMessage, 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  if (showEmailVerification && pendingRegistration) {
    return (
      <EmailVerification
        email={pendingRegistration.email}
        onVerificationSuccess={handleEmailVerificationSuccess}
        onCancel={handleEmailVerificationCancel}
        showToast={showToast || (() => {})}
        isRegistration={true}
      />
    );
  }

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
          
          {!showCustomInput ? (
            <select
              id="register-device-name"
              value={deviceName}
              onChange={handleDeviceNameChange}
              onBlur={() => validateDeviceName(deviceName)}
              required
              aria-describedby={deviceNameError ? "device-name-error" : "device-info"}
              disabled={loading}
            >
              {deviceOptions.map((option, index) => (
                <option key={index} value={option}>
                  {option}
                </option>
              ))}
            </select>
          ) : (
            <input
              id="register-device-name"
              type="text"
              placeholder="Enter custom device name"
              value={deviceName}
              onChange={handleDeviceNameChange}
              onBlur={() => validateDeviceName(deviceName)}
              required
              aria-describedby={deviceNameError ? "device-name-error" : "device-info"}
              disabled={loading}
              autoComplete="off"
            />
          )}
          
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