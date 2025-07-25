import React, { useEffect, useState } from 'react';

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