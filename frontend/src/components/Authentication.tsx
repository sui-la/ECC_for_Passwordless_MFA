import React, { useState } from 'react';
import { getChallenge, verify } from '../services/api';
import { loadPrivateKey, getDeviceId, saveSessionSharedSecret } from '../services/storage';
import { 
  generateECDHKeyPair, 
  exportECDHPublicKey, 
  importECDHPublicKey, 
  deriveSharedSecret, 
  signMessage 
} from '../services/crypto';
import { sendECDHPublicKey } from '../services/api';
import EmailVerification from './EmailVerification';

interface Props {
  onAuth?: (jwt: string) => void;
  showToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
}

const Authentication: React.FC<Props> = ({ onAuth, showToast }) => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [showEmailVerification, setShowEmailVerification] = useState(false);
  const [pendingAuthentication, setPendingAuthentication] = useState<{
    email: string;
  } | null>(null);

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

  const handleEmailVerificationSuccess = async (authData?: { token: string; server_ecdh_public_key: string; session_id: string }) => {
    if (!pendingAuthentication) return;
    
    try {
      if (authData) {
        // Automatic authentication was successful - handle the response
        console.log('✅ Email verification successful, please reauthenticate one more time');
        
        const { token, server_ecdh_public_key } = authData;
        
        if (typeof token !== "string" || !token.trim()) {
          throw new Error('No authentication token received');
        }
        if (!server_ecdh_public_key) {
          throw new Error('No server ECDH public key received');
        }
        
        // Complete ECDH key exchange
        const clientECDHKeyPair = await generateECDHKeyPair();
        const clientECDHPublicKeyPem = await exportECDHPublicKey(clientECDHKeyPair.publicKey);
        await sendECDHPublicKey(clientECDHPublicKeyPem);
        
        const serverECDHPublicKey = await importECDHPublicKey(server_ecdh_public_key);
        const sharedSecret = await deriveSharedSecret(clientECDHKeyPair.privateKey, serverECDHPublicKey);
        saveSessionSharedSecret(sharedSecret);
        
        // Store JWT and complete authentication
        localStorage.setItem('jwt', token);
        onAuth?.(token);
        showToast?.('Authentication successful! Welcome back.', 'success');
        
        setShowEmailVerification(false);
        setPendingAuthentication(null);
      } else {
        // Fallback to manual authentication (for backward compatibility)
        console.log('🔄 Falling back to manual authentication after email verification');
        
        // Add a small delay to ensure Redis has propagated the email verification status
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Get a fresh challenge and create a new signature after email verification
        const challengeResp = await getChallenge(pendingAuthentication.email);
        const nonce = challengeResp.nonce;
        if (!nonce) throw new Error('No challenge received');
        
        const privateKey = await loadPrivateKey();
        if (!privateKey) throw new Error('No private key found. Please register first.');
        
        const signatureBase64 = await signMessage(privateKey, nonce);
        
        // Get the current device ID instead of using the stored one
        const currentDeviceId = await getDeviceId();
        console.log('Using current device ID for verification:', currentDeviceId);
        
        // Try authentication with retry mechanism
        let verifyResp: any;
        let retryCount = 0;
        const maxRetries = 3;
        
        while (retryCount < maxRetries) {
          try {
            console.log(`🔄 Authentication attempt ${retryCount + 1}/${maxRetries}`);
            
            // Now verify with the fresh signature and current device ID
            verifyResp = await verify(
              pendingAuthentication.email, 
              signatureBase64, 
              currentDeviceId || undefined
            );
            
            console.log('🔍 Email verification success - verify response:', verifyResp);
            console.log('🔍 Response type:', typeof verifyResp);
            console.log('🔍 Response keys:', Object.keys(verifyResp));
            
            // Check if we got a verification requirement again (shouldn't happen after verification)
            if ('requires_verification' in verifyResp && verifyResp.requires_verification) {
              console.log('❌ Unexpected verification requirement after email verification');
              throw new Error('Unexpected verification requirement after email verification');
            }
            
            // Check if we have the expected success response
            if (!('token' in verifyResp)) {
              console.log('❌ No token in response. Full response:', verifyResp);
              if (retryCount < maxRetries - 1) {
                console.log('⏳ Retrying in 2 seconds...');
                await new Promise(resolve => setTimeout(resolve, 2000));
                retryCount++;
                continue;
              }
              throw new Error('No authentication token received');
            }
            
            // Success! Break out of retry loop
            break;
            
          } catch (error) {
            console.log(`❌ Authentication attempt ${retryCount + 1} failed:`, error);
            if (retryCount < maxRetries - 1) {
              console.log('⏳ Retrying in 2 seconds...');
              await new Promise(resolve => setTimeout(resolve, 2000));
              retryCount++;
            } else {
              throw error;
            }
          }
        }
        
        // Type guard to ensure we have the success response
        if (!verifyResp || !('token' in verifyResp)) {
          throw new Error('No authentication token received after retries');
        }
        
        const { token, server_ecdh_public_key } = verifyResp;
        console.log('✅ Token received:', token ? 'Present' : 'Missing');
        console.log('✅ Server ECDH public key received:', server_ecdh_public_key ? 'Present' : 'Missing');
        
        if (typeof token !== "string" || !token.trim()) {
          console.log('❌ Token is invalid:', token);
          throw new Error('No authentication token received');
        }
        if (!server_ecdh_public_key) {
          console.log('❌ Server ECDH public key is missing');
          throw new Error('No server ECDH public key received');
        }
        
        // Complete ECDH key exchange
        const clientECDHKeyPair = await generateECDHKeyPair();
        const clientECDHPublicKeyPem = await exportECDHPublicKey(clientECDHKeyPair.publicKey);
        await sendECDHPublicKey(clientECDHPublicKeyPem);
        
        const serverECDHPublicKey = await importECDHPublicKey(server_ecdh_public_key);
        const sharedSecret = await deriveSharedSecret(clientECDHKeyPair.privateKey, serverECDHPublicKey);
        saveSessionSharedSecret(sharedSecret);
        
        // Store JWT and complete authentication
        localStorage.setItem('jwt', token);
        onAuth?.(token);
        showToast?.('Authentication successful! Welcome back.', 'success');
        
        setShowEmailVerification(false);
        setPendingAuthentication(null);
      }
    } catch (err: any) {
      console.error('Authentication error after email verification:', err);
      showToast?.('Authentication failed after verification: ' + (err?.message || err), 'error');
      setShowEmailVerification(false);
      setPendingAuthentication(null);
    }
  };

  const handleEmailVerificationCancel = () => {
    setShowEmailVerification(false);
    setPendingAuthentication(null);
    showToast?.('Authentication cancelled.', 'info');
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
      
      console.log('🔍 Loading private key...');
      const privateKey = await loadPrivateKey();
      console.log('🔍 Private key loaded:', privateKey ? 'Found' : 'Not found');
      if (!privateKey) throw new Error('No private key found. Please register first.');
      let signatureBase64: string;
      try {
        signatureBase64 = await signMessage(privateKey, nonce);
      } catch (signErr: any) {
        throw new Error('Failed to sign challenge: ' + (signErr?.message || signErr));
      }
      // Get the device ID for this private key
      const deviceId = await getDeviceId();
      console.log('Retrieved device ID from storage:', deviceId);
      console.log('Device ID type:', typeof deviceId);
      console.log('Device ID is null:', deviceId === null);
      console.log('Device ID is undefined:', deviceId === undefined);
      
      const verifyResp = await verify(email, signatureBase64, deviceId || undefined);
      console.log('verifyResp:', verifyResp, typeof verifyResp, Object.keys(verifyResp));
      
      // Check if email verification is required
      console.log('🔍 Checking for email verification requirement...');
      console.log('🔍 verifyResp keys:', Object.keys(verifyResp));
      console.log('🔍 requires_verification in verifyResp:', 'requires_verification' in verifyResp);
      
      const isVerificationRequired = 'requires_verification' in verifyResp && verifyResp.requires_verification;
      console.log('🔍 isVerificationRequired:', isVerificationRequired);
      
      if (isVerificationRequired) {
        console.log('🔍 Email verification required! Setting up verification...');
        setPendingAuthentication({
          email,
        });
        setShowEmailVerification(true);
        setEmail('');
        console.log('🔍 Email verification state set, returning...');
        return;
      }
      
      // --- ECDH Key Exchange ---
      if (!('token' in verifyResp)) {
        throw new Error('Unexpected response format from verification');
      }
      
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
      saveSessionSharedSecret(sharedSecret);
      onAuth?.(token);
      showToast?.('Authentication successful! Welcome back.', 'success');
      setEmail('');
    } catch (err: any) {
      console.error('Authentication error:', err);
      
      // SECURITY FIX: Handle specific error codes with user-friendly messages
      if (err?.response?.data?.code === 'EMAIL_NOT_VERIFIED') {
        const message = err.response.data.message || 'Please verify your email address before authenticating. Check your email for the verification code.';
        setError(message);
        showToast?.(message, 'error');
        
        // Set up email verification for this user
        setPendingAuthentication({ email });
        setShowEmailVerification(true);
        setEmail('');
      } else {
        const errorMessage = err?.message || err || 'Authentication failed';
        setError(errorMessage);
        showToast?.('Authentication failed: ' + errorMessage, 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  if (showEmailVerification && pendingAuthentication) {
    return (
      <EmailVerification
        email={pendingAuthentication.email}
        onVerificationSuccess={handleEmailVerificationSuccess}
        onCancel={handleEmailVerificationCancel}
        showToast={showToast || (() => {})}
        isRegistration={false}
      />
    );
  }

  return (
    <section className="section" aria-labelledby="authentication-title">
      <h2 id="authentication-title">Authenticate</h2>
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

      
    </section>
  );
};

export default Authentication; 