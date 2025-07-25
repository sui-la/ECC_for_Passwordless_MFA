import React, { useState } from 'react';
import { generateKeyPair, exportPublicKey } from '../services/crypto';
import { savePrivateKey } from '../services/storage';
import { register } from '../services/api';

interface RegistrationProps {
  showToast: (message: string, type?: 'success' | 'error' | 'info') => void;
}

const Registration: React.FC<RegistrationProps> = ({ showToast }) => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);

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

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setEmail(value);
    if (emailError) {
      validateEmail(value);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!validateEmail(email)) {
      return;
    }

    setLoading(true);
    try {
      const { privateKey, publicKey } = await generateKeyPair();
      await savePrivateKey(privateKey);
      const publicKeyPem = await exportPublicKey(publicKey);
      await register(email, publicKeyPem);
      showToast('Registration successful! You can now authenticate.', 'success');
      setEmail('');
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