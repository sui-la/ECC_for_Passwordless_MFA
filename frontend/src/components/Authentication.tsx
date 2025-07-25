import React, { useState } from 'react';
import { getChallenge, verify } from '../services/api';
import { loadPrivateKey } from '../services/storage';

interface Props {
  onAuth: (jwt: string) => void;
  showToast: (message: string, type?: 'success' | 'error' | 'info') => void;
}

const Authentication: React.FC<Props> = ({ onAuth, showToast }) => {
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

  const handleAuthenticate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!validateEmail(email)) {
      return;
    }

    setLoading(true);
    try {
      const challengeResp = await getChallenge(email);
      const nonce = challengeResp.nonce;
      if (!nonce) throw new Error('No challenge received');
      
      const privateKey = await loadPrivateKey();
      if (!privateKey) throw new Error('No private key found. Please register first.');
      
      const enc = new TextEncoder();
      const signature = await window.crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        enc.encode(nonce)
      );
      const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
      const verifyResp = await verify(email, signatureBase64);
      localStorage.setItem('jwt', verifyResp.token);
      onAuth(verifyResp.token);
      showToast('Authentication successful! Welcome back.', 'success');
      setEmail('');
    } catch (err: any) {
      const errorMessage = err?.message || err || 'Authentication failed';
      setError(errorMessage);
      showToast('Authentication failed: ' + errorMessage, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="section" aria-labelledby="authentication-title">
      <h2 id="authentication-title">Authenticate</h2>
      <p className="section-description">
        Sign in to your account using your email address. Your device will use your stored private key to prove your identity.
      </p>
      
      <form onSubmit={handleAuthenticate} noValidate aria-describedby={error ? "authentication-error" : undefined}>
        <div className="form-group">
          <label htmlFor="auth-email" className="form-label">
            Email Address <span aria-label="required" className="required">*</span>
          </label>
          <input
            id="auth-email"
            type="email"
            placeholder="Enter your email address"
            value={email}
            onChange={handleEmailChange}
            onBlur={() => validateEmail(email)}
            required
            aria-describedby={emailError ? "auth-email-error" : undefined}
            disabled={loading}
            autoComplete="email"
          />
          {emailError && (
            <div id="auth-email-error" className="error-message" role="alert" aria-live="polite">
              {emailError}
            </div>
          )}
        </div>

        {error && (
          <div id="authentication-error" className="error-message" role="alert" aria-live="polite">
            {error}
          </div>
        )}

        <button 
          type="submit" 
          disabled={loading}
          aria-describedby={loading ? "auth-loading" : undefined}
        >
          {loading ? (
            <>
              <span aria-hidden="true">🔐</span>
              <span id="auth-loading">Authenticating...</span>
            </>
          ) : (
            'Authenticate'
          )}
        </button>
      </form>

      <div className="info-box" role="note" aria-label="Authentication information">
        <h3>How authentication works</h3>
        <ol>
          <li>Enter your registered email address</li>
          <li>Our server sends a unique challenge to your device</li>
          <li>Your device signs the challenge with your private key</li>
          <li>The server verifies your signature using your public key</li>
          <li>You're granted access without ever sending a password</li>
        </ol>
      </div>
    </section>
  );
};

export default Authentication; 