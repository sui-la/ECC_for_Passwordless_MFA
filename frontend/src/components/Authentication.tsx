import React, { useState } from 'react';
import { getChallenge, verify } from '../services/api';
import { loadPrivateKey } from '../services/storage';
import { 
  generateECDHKeyPair, 
  exportECDHPublicKey, 
  importECDHPublicKey, 
  deriveSharedSecret 
} from '../services/crypto';
import { sendECDHPublicKey } from '../services/api';

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
      const verifyRespRaw = await verify(email, signatureBase64);
      console.log('verifyResp:', verifyRespRaw, typeof verifyRespRaw, Object.keys(verifyRespRaw));
      const verifyResp = typeof verifyRespRaw === 'string' ? JSON.parse(verifyRespRaw) : verifyRespRaw;
      // --- ECDH Key Exchange ---
      const { token, server_ecdh_public_key } = verifyResp;
      console.log('token:', token, typeof token, token && token.length);
      console.log('token === undefined:', token === undefined);
      console.log('token === null:', token === null);
      console.log('token === "":', token === "");
      console.log('typeof token:', typeof token);
      console.log('token.trim():', token.trim());
      console.log('!token.trim():', !token.trim());
      if (typeof token !== "string" || !token.trim()) {
        console.error('No authentication token found in verifyResp:', verifyResp);
        throw new Error('No authentication token found [DEBUG-2]');
      }
      if (!server_ecdh_public_key) {
        console.error('No server ECDH public key found in verifyResp:', verifyResp);
        throw new Error('No server ECDH public key received');
      }
      // 1. Generate client ECDH key pair
      const clientECDHKeyPair = await generateECDHKeyPair();
      // 2. Export client ECDH public key (PEM)
      const clientECDHPublicKeyPem = await exportECDHPublicKey(clientECDHKeyPair.publicKey);
      // 3. Send client ECDH public key to backend
      console.log('Setting jwt in localStorage:', token);
      localStorage.setItem('jwt', token);
      console.log('jwt in localStorage after set:', localStorage.getItem('jwt'));
      await sendECDHPublicKey(clientECDHPublicKeyPem);
      // 4. Import server ECDH public key
      const serverECDHPublicKey = await importECDHPublicKey(server_ecdh_public_key);
      // 5. Derive shared secret
      const sharedSecret = await deriveSharedSecret(clientECDHKeyPair.privateKey, serverECDHPublicKey);
      // Store shared secret in memory (for demo; replace with secure storage as needed)
      (window as any).sessionSharedSecret = sharedSecret;
      onAuth(token);
      showToast('Authentication successful! Welcome back.', 'success');
      setEmail('');
    } catch (err: any) {
      console.error('Authentication error:', err);
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