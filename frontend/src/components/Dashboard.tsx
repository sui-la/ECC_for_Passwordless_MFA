import React, { useEffect, useState } from 'react';
import { sendSecureData } from '../services/api';
import { importAesKeyFromSharedSecret, aesGcmEncrypt, aesGcmDecrypt } from '../services/crypto';

interface Props {
  jwt: string | null;
}

interface UserInfo {
  email?: string;
  iat?: number;
  exp?: number;
  [key: string]: any;
}

const Dashboard: React.FC<Props> = ({ jwt }) => {
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [secureMessage, setSecureMessage] = useState('');
  const [secureResponse, setSecureResponse] = useState<string | null>(null);
  const [secureError, setSecureError] = useState<string | null>(null);
  const [secureLoading, setSecureLoading] = useState(false);

  useEffect(() => {
    if (jwt) {
      try {
        setLoading(true);
        setError(null);
        const payload = jwt.split('.')[1];
        const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
        setUserInfo(decoded);
      } catch (err) {
        setError('Failed to decode user information');
        setUserInfo(null);
      } finally {
        setLoading(false);
      }
    } else {
      setUserInfo(null);
      setLoading(false);
    }
  }, [jwt]);

  const handleCopy = async () => {
    if (userInfo) {
      try {
        await navigator.clipboard.writeText(JSON.stringify(userInfo, null, 2));
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (err) {
        setError('Failed to copy to clipboard');
      }
    }
  };

  const formatDate = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const handleSendSecure = async (e: React.FormEvent) => {
    e.preventDefault();
    setSecureError(null);
    setSecureResponse(null);
    setSecureLoading(true);
    try {
      // Get the session shared secret from window
      const sharedSecret = (window as any).sessionSharedSecret;
      if (!sharedSecret) throw new Error('No session shared secret found. Please re-authenticate.');
      const aesKey = await importAesKeyFromSharedSecret(sharedSecret);
      // Encrypt the message
      const { ciphertext, iv } = await aesGcmEncrypt(secureMessage, aesKey);
      // Send full ciphertext (with tag appended) and iv
      const resp = await sendSecureData(ciphertext, iv);
      // Decrypt response (full ciphertext with tag appended)
      const decrypted = await aesGcmDecrypt(
        resp.ciphertext,
        resp.iv,
        aesKey
      );
      setSecureResponse(decrypted);
    } catch (err: any) {
      setSecureError(err?.message || err || 'Secure data exchange failed');
    } finally {
      setSecureLoading(false);
    }
  };

  return (
    <section className="dashboard-card" aria-labelledby="dashboard-title">
      <header className="dashboard-header">
        <div className="dashboard-avatar" aria-hidden="true" title="User avatar">👤</div>
        <div>
          <h2 id="dashboard-title" className="dashboard-welcome">
            Welcome{userInfo && userInfo.email ? `,` : ''}
          </h2>
          {userInfo && userInfo.email && (
            <p className="dashboard-email" aria-label="User email address">
              {userInfo.email}
            </p>
          )}
        </div>
      </header>

      <hr className="dashboard-divider" aria-hidden="true" />

      <div className="dashboard-content">
        <h3 style={{ margin: '10px 0 6px 0', fontWeight: 600 }}>User Information</h3>
        
        {loading && (
          <div className="loading-indicator" role="status" aria-live="polite">
            <span aria-hidden="true">⏳</span> Loading user information...
          </div>
        )}

        {error && (
          <div className="alert alert-error" role="alert" aria-live="polite">
            <span aria-hidden="true">⚠️</span> {error}
          </div>
        )}

        {!loading && !error && userInfo ? (
          <div className="dashboard-info-block">
            <div className="user-info-details">
              <h4>Account Details</h4>
              <dl>
                {userInfo.email && (
                  <>
                    <dt>Email Address</dt>
                    <dd>{userInfo.email}</dd>
                  </>
                )}
                {userInfo.iat && (
                  <>
                    <dt>Token Issued</dt>
                    <dd>{formatDate(userInfo.iat)}</dd>
                  </>
                )}
                {userInfo.exp && (
                  <>
                    <dt>Token Expires</dt>
                    <dd>{formatDate(userInfo.exp)}</dd>
                  </>
                )}
              </dl>
            </div>

            <div className="token-details">
              <h4>Full Token Data</h4>
              <div className="json-display" role="textbox" aria-label="JSON token data">
                <pre style={{ 
                  margin: 0, 
                  fontFamily: 'Fira Mono, Consolas, monospace', 
                  background: 'none', 
                  color: 'inherit',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word'
                }}>
                  {JSON.stringify(userInfo, null, 2)}
                </pre>
              </div>
              
              <button 
                className="dashboard-copy-btn" 
                onClick={handleCopy}
                aria-label={copied ? "User information copied to clipboard" : "Copy user information to clipboard"}
                aria-describedby={copied ? "copy-success" : undefined}
              >
                {copied ? (
                  <>
                    <span aria-hidden="true">✓</span>
                    <span id="copy-success">Copied!</span>
                  </>
                ) : (
                  <>
                    <span aria-hidden="true">📋</span>
                    Copy
                  </>
                )}
              </button>
            </div>
          </div>
        ) : !loading && !error && (
          <div className="alert alert-info" role="alert">
            <span aria-hidden="true">ℹ️</span> No user information available.
          </div>
        )}
        <hr className="dashboard-divider" aria-hidden="true" style={{ margin: '24px 0' }} />
        <h3 style={{ margin: '10px 0 6px 0', fontWeight: 600 }}>Secure Data Exchange Demo</h3>
        <form onSubmit={handleSendSecure} style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
          <label htmlFor="secure-message" style={{ fontWeight: 500, marginBottom: 4 }}>Message to send securely:</label>
          <input
            id="secure-message"
            type="text"
            value={secureMessage}
            onChange={e => setSecureMessage(e.target.value)}
            disabled={secureLoading}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #3a506b',
              background: '#232b3e',
              color: '#e0e6f0',
              fontSize: '1em',
              marginBottom: 8
            }}
            placeholder="Type your message..."
          />
          <button
            type="submit"
            disabled={secureLoading || !secureMessage}
            style={{
              background: secureLoading || !secureMessage ? '#3a506b' : '#2196f3',
              color: '#fff',
              border: 'none',
              borderRadius: 6,
              padding: '8px 16px',
              fontWeight: 600,
              fontSize: '1em',
              cursor: secureLoading || !secureMessage ? 'not-allowed' : 'pointer',
              transition: 'background 0.2s',
              marginTop: 2,
              alignSelf: 'flex-start'
            }}
          >
            {secureLoading ? 'Sending...' : 'Send Securely'}
          </button>
        </form>
        {secureError && (
          <div className="alert alert-error" role="alert" aria-live="polite" style={{ marginTop: 10 }}>
            <span aria-hidden="true">⚠️</span> {secureError}
          </div>
        )}
        {secureResponse && (
          <div className="alert alert-success" role="status" aria-live="polite" style={{ marginTop: 10 }}>
            <span aria-hidden="true">🔐</span> Response: <strong>{secureResponse}</strong>
          </div>
        )}
      </div>

      <footer className="dashboard-footer">
        <p className="dashboard-status">
          <span aria-hidden="true">🔒</span>
          <span>Authentication Status: </span>
          <strong>{userInfo ? 'Authenticated' : 'Not Authenticated'}</strong>
        </p>
      </footer>
    </section>
  );
};

export default Dashboard; 