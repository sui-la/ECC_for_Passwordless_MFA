import React, { useState, useEffect } from 'react';
import { initiateRecovery, verifyRecoveryToken, completeRecovery } from '../services/api';
import { generateKeyPair, exportPublicKey } from '../services/crypto';
import { savePrivateKey } from '../services/storage';
import { generateDeviceName, detectDeviceInfo } from '../utils/deviceDetection';

interface RecoveryProps {
  showToast?: (message: string, type: 'success' | 'error' | 'info') => void;
  onBack?: () => void;
}

const Recovery: React.FC<RecoveryProps> = ({ showToast, onBack }) => {
  const [step, setStep] = useState<'initiate' | 'verify' | 'complete'>('initiate');
  const [email, setEmail] = useState('');
  const [recoveryToken, setRecoveryToken] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [userEmail, setUserEmail] = useState('');

  useEffect(() => {
    // Check if recovery token is in URL using native URLSearchParams
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (token) {
      setRecoveryToken(token);
      setStep('verify');
      verifyToken(token);
    }
  }, []);

  useEffect(() => {
    // Auto-detect device name
    try {
      const deviceInfo = detectDeviceInfo();
      const autoDeviceName = generateDeviceName(deviceInfo);
      setDeviceName(autoDeviceName);
    } catch (err) {
      console.warn('Failed to auto-detect device:', err);
      setDeviceName('Recovery Device');
    }
  }, []);

  const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const handleInitiateRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!validateEmail(email)) {
      setError('Please enter a valid email address.');
      return;
    }

    setLoading(true);
    try {
      await initiateRecovery(email);
      showToast?.('Recovery email sent! Check your inbox for the recovery link.', 'success');
      setEmail('');
    } catch (err: any) {
      setError(err.message || 'Failed to initiate recovery');
      showToast?.(err.message || 'Failed to initiate recovery', 'error');
    } finally {
      setLoading(false);
    }
  };

  const verifyToken = async (token: string) => {
    setLoading(true);
    try {
      const response = await verifyRecoveryToken(token);
      setUserEmail(response.email);
      setStep('complete');
    } catch (err: any) {
      setError(err.message || 'Invalid or expired recovery token');
      showToast?.(err.message || 'Invalid or expired recovery token', 'error');
      setStep('initiate');
    } finally {
      setLoading(false);
    }
  };

  const handleCompleteRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!deviceName.trim()) {
      setError('Please enter a device name.');
      return;
    }

    setLoading(true);
    try {
      // Generate new key pair for recovery
      const keyPair = await generateKeyPair();
      const publicKeyPem = await exportPublicKey(keyPair.publicKey);
      
      // Complete recovery
      const response = await completeRecovery(recoveryToken, publicKeyPem, deviceName.trim());
      
      // Save the private key locally for authentication
      if (response && response.device_id) {
        await savePrivateKey(keyPair.privateKey, response.device_id);
      } else {
        await savePrivateKey(keyPair.privateKey);
      }
      
      showToast?.('Account recovery completed successfully! You can now authenticate with your new device.', 'success');
      setStep('initiate');
      setEmail('');
      setDeviceName('');
      setRecoveryToken('');
    } catch (err: any) {
      setError(err.message || 'Failed to complete recovery');
      showToast?.(err.message || 'Failed to complete recovery', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleManualTokenVerification = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recoveryToken.trim()) {
      setError('Please enter the recovery token.');
      return;
    }
    await verifyToken(recoveryToken);
  };

  if (loading) {
    return (
      <div style={{ 
        textAlign: 'center', 
        padding: '2rem',
        color: 'var(--color-main)'
      }}>
        <div style={{ 
          fontSize: '1.2em',
          marginBottom: '1rem'
        }}>
          {step === 'initiate' && 'Sending recovery email...'}
          {step === 'verify' && 'Verifying recovery token...'}
          {step === 'complete' && 'Completing recovery...'}
        </div>
      </div>
    );
  }

  return (
    <div style={{ 
      maxWidth: '100%',
      color: 'var(--color-main)'
    }}>
      {/* Back Button */}
      <button
        onClick={onBack}
        style={{
          background: 'none',
          border: '1px solid var(--color-border)',
          color: 'var(--color-main)',
          borderRadius: 6,
          padding: '8px 16px',
          fontSize: '0.9em',
          cursor: 'pointer',
          marginBottom: '1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}
        aria-label="Go back to main page"
      >
        ← Back
      </button>

      <h2 style={{ 
        marginBottom: '1rem',
        fontSize: '1.8em',
        fontWeight: '600',
        color: 'var(--color-main)'
      }}>
        Account Recovery
      </h2>
      
      {error && (
        <div style={{
          background: 'var(--color-error)',
          color: '#fff',
          padding: '12px 16px',
          borderRadius: '8px',
          marginBottom: '1rem',
          border: '1px solid rgba(255,255,255,0.2)'
        }}>
          {error}
        </div>
      )}

      {step === 'initiate' && (
        <div>
          <p style={{ 
            marginBottom: '2rem',
            color: 'var(--color-main)',
            opacity: 0.8
          }}>
            If you've lost access to your device or private key, you can recover your account using your email address.
          </p>
          
          <form onSubmit={handleInitiateRecovery}>
            <div style={{ marginBottom: '1rem' }}>
              <label htmlFor="recovery-email" style={{ 
                display: 'block', 
                marginBottom: 6, 
                fontWeight: 500,
                color: 'var(--color-main)',
                fontSize: '0.9em'
              }}>
                Email Address
              </label>
              <input
                id="recovery-email"
                type="email"
                placeholder="Enter your registered email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={loading}
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  borderRadius: 8,
                  border: '1px solid var(--color-border)',
                  background: 'var(--bg-card)',
                  color: 'var(--color-main)',
                  fontSize: '1em',
                  minHeight: '44px',
                  boxSizing: 'border-box'
                }}
              />
            </div>
            <button
              type="submit"
              disabled={loading || !email.trim()}
              style={{
                width: '100%',
                background: loading || !email.trim() ? 'var(--color-border)' : 'var(--color-accent)',
                color: '#fff',
                border: 'none',
                borderRadius: 8,
                padding: '12px 16px',
                fontWeight: 600,
                fontSize: '1em',
                cursor: loading || !email.trim() ? 'not-allowed' : 'pointer',
                minHeight: '44px'
              }}
            >
              Send Recovery Email
            </button>
          </form>
        </div>
      )}

      {step === 'verify' && (
        <div>
          <p style={{ 
            marginBottom: '2rem',
            color: 'var(--color-main)',
            opacity: 0.8
          }}>
            Enter the recovery token from your email to verify your identity.
          </p>
          
          <form onSubmit={handleManualTokenVerification}>
            <div style={{ marginBottom: '1rem' }}>
              <label htmlFor="recovery-token" style={{ 
                display: 'block', 
                marginBottom: 6, 
                fontWeight: 500,
                color: 'var(--color-main)',
                fontSize: '0.9em'
              }}>
                Recovery Token
              </label>
              <input
                id="recovery-token"
                type="text"
                placeholder="Enter recovery token from email"
                value={recoveryToken}
                onChange={(e) => setRecoveryToken(e.target.value)}
                disabled={loading}
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  borderRadius: 8,
                  border: '1px solid var(--color-border)',
                  background: 'var(--bg-card)',
                  color: 'var(--color-main)',
                  fontSize: '1em',
                  minHeight: '44px',
                  boxSizing: 'border-box'
                }}
              />
            </div>
            <button
              type="submit"
              disabled={loading || !recoveryToken.trim()}
              style={{
                width: '100%',
                background: loading || !recoveryToken.trim() ? 'var(--color-border)' : 'var(--color-accent)',
                color: '#fff',
                border: 'none',
                borderRadius: 8,
                padding: '12px 16px',
                fontWeight: 600,
                fontSize: '1em',
                cursor: loading || !recoveryToken.trim() ? 'not-allowed' : 'pointer',
                minHeight: '44px'
              }}
            >
              Verify Token
            </button>
          </form>
        </div>
      )}

      {step === 'complete' && (
        <div>
          <p style={{ 
            marginBottom: '2rem',
            color: 'var(--color-main)',
            opacity: 0.8
          }}>
            Recovery token verified for <strong>{userEmail}</strong>. 
            Enter a name for your new recovery device to complete the process.
          </p>
          
          <form onSubmit={handleCompleteRecovery}>
            <div style={{ marginBottom: '1rem' }}>
              <label htmlFor="recovery-device-name" style={{ 
                display: 'block', 
                marginBottom: 6, 
                fontWeight: 500,
                color: 'var(--color-main)',
                fontSize: '0.9em'
              }}>
                Device Name
              </label>
              <input
                id="recovery-device-name"
                type="text"
                placeholder="e.g., Recovery Device, New Phone"
                value={deviceName}
                onChange={(e) => setDeviceName(e.target.value)}
                disabled={loading}
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  borderRadius: 8,
                  border: '1px solid var(--color-border)',
                  background: 'var(--bg-card)',
                  color: 'var(--color-main)',
                  fontSize: '1em',
                  minHeight: '44px',
                  boxSizing: 'border-box'
                }}
              />
            </div>
            <button
              type="submit"
              disabled={loading || !deviceName.trim()}
              style={{
                width: '100%',
                background: loading || !deviceName.trim() ? 'var(--color-border)' : 'var(--color-accent)',
                color: '#fff',
                border: 'none',
                borderRadius: 8,
                padding: '12px 16px',
                fontWeight: 600,
                fontSize: '1em',
                cursor: loading || !deviceName.trim() ? 'not-allowed' : 'pointer',
                minHeight: '44px'
              }}
            >
              Complete Recovery
            </button>
          </form>
        </div>
      )}
    </div>
  );
};

export default Recovery; 