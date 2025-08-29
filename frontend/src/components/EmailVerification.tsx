import React, { useState, useEffect } from 'react';
import { verifyEmailCode, sendEmailVerification } from '../services/api';

interface EmailVerificationProps {
  email?: string;
  onVerificationSuccess?: (authData?: { token: string; server_ecdh_public_key: string; session_id: string }) => void;
  onCancel?: () => void;
  showToast?: (message: string, type: 'success' | 'error' | 'info') => void;
  isRegistration?: boolean;
}

const EmailVerification: React.FC<EmailVerificationProps> = ({ 
  email, 
  onVerificationSuccess, 
  onCancel, 
  showToast,
  isRegistration = false
}) => {
  const [verificationCode, setVerificationCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timeLeft, setTimeLeft] = useState(600); // 10 minutes in seconds

  useEffect(() => {
    // Countdown timer
    const timer = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  const handleVerifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verificationCode.trim()) {
      setError('Please enter the verification code');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      if (!email) {
        setError('Email is required for verification');
        return;
      }
      const result = await verifyEmailCode(email, verificationCode.trim());
      
      if (isRegistration) {
        // For registration, just show success message
        showToast?.('Email verification successful!', 'success');
        onVerificationSuccess?.();
      } else {
        // For authentication, handle automatic authentication
        if (result.token && result.server_ecdh_public_key && result.session_id) {
          showToast?.('Email verification and authentication successful!', 'success');
          onVerificationSuccess?.({
            token: result.token,
            server_ecdh_public_key: result.server_ecdh_public_key,
            session_id: result.session_id
          });
        } else {
          showToast?.('Email verification successful!', 'success');
          onVerificationSuccess?.();
        }
      }
    } catch (err: any) {
      setError(err.message || 'Failed to verify code');
      showToast?.(err.message || 'Failed to verify code', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleResendCode = async () => {
    setResending(true);
    setError(null);

    try {
      if (!email) {
        setError('Email is required for resending verification code');
        return;
      }
      await sendEmailVerification(email);
      setTimeLeft(600); // Reset timer
      showToast?.('Verification code resent successfully!', 'success');
    } catch (err: any) {
      setError(err.message || 'Failed to resend code');
      showToast?.(err.message || 'Failed to resend code', 'error');
    } finally {
      setResending(false);
    }
  };

  const handleCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, '').slice(0, 6); // Only allow digits, max 6
    setVerificationCode(value);
    if (error) setError(null);
  };

  return (
    <div style={{ 
      maxWidth: '100%',
      color: 'var(--color-main)'
    }}>
      <h2 style={{ 
        marginBottom: '1rem',
        fontSize: '1.8em',
        fontWeight: '600',
        color: 'var(--color-main)'
      }}>
        Email Verification
      </h2>
      
      <p style={{ 
        marginBottom: '2rem',
        color: 'var(--color-main)',
        opacity: 0.8
      }}>
        {isRegistration 
          ? 'Please check your email for a 6-digit verification code to complete your registration.'
          : 'Please check your email for a 6-digit verification code to continue with authentication.'
        }
      </p>

      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--color-border)',
        borderRadius: '12px',
        padding: '1.5rem',
        marginBottom: '1rem'
      }}>
        <div style={{ 
          fontSize: '0.9em',
          color: 'var(--color-main)',
          opacity: 0.8,
          marginBottom: '1rem'
        }}>
          Code sent to: <strong>{email}</strong>
        </div>
        
        {timeLeft > 0 && (
          <div style={{ 
            fontSize: '0.9em',
            color: 'var(--color-accent)',
            marginBottom: '1rem'
          }}>
            Time remaining: <strong>{formatTime(timeLeft)}</strong>
          </div>
        )}
        
        {timeLeft === 0 && (
          <div style={{ 
            fontSize: '0.9em',
            color: '#ff1744',
            marginBottom: '1rem'
          }}>
            Code expired. Please request a new code.
          </div>
        )}
      </div>

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

      <form onSubmit={handleVerifyCode}>
        <div style={{ marginBottom: '1rem' }}>
          <label htmlFor="verification-code" style={{ 
            display: 'block', 
            marginBottom: 6, 
            fontWeight: 500,
            color: 'var(--color-main)',
            fontSize: '0.9em'
          }}>
            Verification Code
          </label>
          <input
            id="verification-code"
            type="text"
            placeholder="Enter 6-digit code"
            value={verificationCode}
            onChange={handleCodeChange}
            disabled={loading || timeLeft === 0}
            style={{
              width: '100%',
              padding: '12px 16px',
              borderRadius: 8,
              border: '1px solid var(--color-border)',
              background: 'var(--bg-card)',
              color: 'var(--color-main)',
              fontSize: '1.2em',
              textAlign: 'center',
              letterSpacing: '0.5em',
              minHeight: '44px',
              boxSizing: 'border-box',
              fontFamily: 'monospace'
            }}
            maxLength={6}
            autoComplete="one-time-code"
          />
        </div>

        <div style={{ 
          display: 'flex', 
          gap: '1rem',
          flexWrap: 'wrap'
        }}>
          <button
            type="submit"
            disabled={loading || !verificationCode.trim() || timeLeft === 0}
            style={{
              flex: '1',
              background: loading || !verificationCode.trim() || timeLeft === 0 ? 'var(--color-border)' : 'var(--color-accent)',
              color: '#fff',
              border: 'none',
              borderRadius: 8,
              padding: '12px 16px',
              fontWeight: 600,
              fontSize: '1em',
              cursor: loading || !verificationCode.trim() || timeLeft === 0 ? 'not-allowed' : 'pointer',
              minHeight: '44px',
              minWidth: '120px'
            }}
          >
            {loading ? 'Verifying...' : 'Verify Code'}
          </button>

          <button
            type="button"
            onClick={handleResendCode}
            disabled={resending || timeLeft > 0}
            style={{
              background: resending || timeLeft > 0 ? 'var(--color-border)' : 'none',
              color: resending || timeLeft > 0 ? 'var(--color-main)' : 'var(--color-accent)',
              border: `1px solid ${resending || timeLeft > 0 ? 'var(--color-border)' : 'var(--color-accent)'}`,
              borderRadius: 8,
              padding: '12px 16px',
              fontWeight: 600,
              fontSize: '1em',
              cursor: resending || timeLeft > 0 ? 'not-allowed' : 'pointer',
              minHeight: '44px',
              minWidth: '120px'
            }}
          >
            {resending ? 'Sending...' : 'Resend Code'}
          </button>

          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            style={{
              background: 'none',
              color: 'var(--color-main)',
              border: '1px solid var(--color-border)',
              borderRadius: 8,
              padding: '12px 16px',
              fontWeight: 600,
              fontSize: '1em',
              cursor: loading ? 'not-allowed' : 'pointer',
              minHeight: '44px',
              minWidth: '120px'
            }}
          >
            Cancel
          </button>
        </div>
      </form>

      <div style={{
        marginTop: '1.5rem',
        padding: '1rem',
        background: 'var(--bg-card)',
        border: '1px solid var(--color-border)',
        borderRadius: '8px',
        fontSize: '0.9em',
        color: 'var(--color-main)',
        opacity: 0.8
      }}>
        <div style={{ marginBottom: '0.5rem', fontWeight: 600 }}>
          Didn't receive the code?
        </div>
        <ul style={{ margin: 0, paddingLeft: '1.5rem' }}>
          <li>Check your spam/junk folder</li>
          <li>Make sure the email address is correct</li>
          <li>Wait a few minutes before requesting a new code</li>
        </ul>
      </div>
    </div>
  );
};

export default EmailVerification; 