import React, { useState, useEffect, useRef } from 'react';
import Registration from './components/Registration';
import Authentication from './components/Authentication';
import Dashboard from './components/Dashboard';
import KeyManagement from './components/KeyManagement';
import BackupKeyManagement from './components/BackupKeyManagement';
import Recovery from './components/Recovery';
import Profile from './components/Profile';
import Toast from './components/Toast';
import './App.css';

const App: React.FC = () => {
  const [jwt, setJwt] = useState<string | null>(null);
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    return (localStorage.getItem('theme') as 'light' | 'dark') || 'dark';
  });
  const [activeComponent, setActiveComponent] = useState<'dashboard' | 'profile' | 'keys' | 'backup'>('dashboard');
  const [showRecovery, setShowRecovery] = useState(false);
  const modalRef = useRef<HTMLDivElement>(null);
  const mainContentRef = useRef<HTMLDivElement>(null);
  const skipLinkRef = useRef<HTMLAnchorElement>(null);

  useEffect(() => {
    const storedJwt = localStorage.getItem('jwt');
    if (storedJwt) setJwt(storedJwt);
  }, []);

  useEffect(() => {
    document.body.classList.toggle('theme-dark', theme === 'dark');
    localStorage.setItem('theme', theme);
  }, [theme]);

  // Trap focus in modal and close on Escape
  useEffect(() => {
    if (!showLogoutModal) return;
    const focusable = modalRef.current?.querySelectorAll<HTMLElement>(
      'button, [tabindex]:not([tabindex="-1"])'
    );
    const first = focusable?.[0];
    const last = focusable?.[focusable.length - 1];
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setShowLogoutModal(false);
      }
      if (e.key === 'Tab' && focusable && focusable.length > 0) {
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener('keydown', handleKey);
    first?.focus();
    return () => document.removeEventListener('keydown', handleKey);
  }, [showLogoutModal]);

  // Announce theme changes to screen readers
  useEffect(() => {
    const announcement = document.createElement('div');
    announcement.setAttribute('aria-live', 'polite');
    announcement.setAttribute('aria-atomic', 'true');
    announcement.style.position = 'absolute';
    announcement.style.left = '-10000px';
    announcement.style.width = '1px';
    announcement.style.height = '1px';
    announcement.style.overflow = 'hidden';
    announcement.textContent = `Switched to ${theme} mode`;
    document.body.appendChild(announcement);
    
    setTimeout(() => {
      document.body.removeChild(announcement);
    }, 1000);
  }, [theme]);

  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    setToast({ message, type });
  };

  const handleAuth = (token: string) => {
    setJwt(token);
  };

  const handleLogout = () => {
    setShowLogoutModal(true);
  };

  const confirmLogout = () => {
    localStorage.removeItem('jwt');
    setJwt(null);
    setShowLogoutModal(false);
    showToast('You have been logged out.', 'info');
    // Focus main content after logout
    mainContentRef.current?.focus();
  };

  const cancelLogout = () => {
    setShowLogoutModal(false);
  };

  const handleSkipLinkClick = (e: React.MouseEvent) => {
    e.preventDefault();
    mainContentRef.current?.focus();
  };

  // Check if we're on recovery page
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const recoveryToken = urlParams.get('token');
    if (recoveryToken) {
      setShowRecovery(true);
    }
  }, []);

  return (
    <>
      {/* Skip to main content link for screen readers */}
      <a
        ref={skipLinkRef}
        href="#main-content"
        className="skip-link"
        onClick={handleSkipLinkClick}
        onFocus={() => skipLinkRef.current?.classList.add('skip-link-visible')}
        onBlur={() => skipLinkRef.current?.classList.remove('skip-link-visible')}
      >
        Skip to main content
      </a>

      <div className="main-container fade-in" role="main" id="main-content" tabIndex={-1} ref={mainContentRef}>
        <header role="banner">
          <h1 style={{ textAlign: 'center', marginBottom: 32, letterSpacing: 1 }}>
            ECC Passwordless Multi-Factor Authentication
          </h1>
        </header>

        {showRecovery ? (
          <main role="main" aria-label="Recovery section">
            <Recovery showToast={showToast} />
          </main>
        ) : !jwt ? (
          <main role="main" aria-label="Authentication section">
            <Registration showToast={showToast} />
            <Authentication onAuth={handleAuth} showToast={showToast} />
            <div style={{ 
              textAlign: 'center', 
              marginTop: '2rem',
              padding: '1rem',
              borderTop: '1px solid var(--color-border)'
            }}>
              <p style={{ 
                marginBottom: '1rem',
                color: 'var(--color-main)',
                opacity: 0.7
              }}>
                Lost access to your device?
              </p>
              <button
                onClick={() => setShowRecovery(true)}
                style={{
                  background: 'none',
                  border: '1px solid var(--color-accent)',
                  color: 'var(--color-accent)',
                  borderRadius: 6,
                  padding: '8px 16px',
                  fontSize: '0.9em',
                  cursor: 'pointer'
                }}
              >
                Recover Account
              </button>
            </div>
          </main>
        ) : (
          <>
            <nav role="navigation" aria-label="Main navigation">
              <div className="navbar-row">
                <div className="tab-group" role="tablist" aria-label="Application sections">
                  <button
                    className={`tab-btn${activeComponent === 'dashboard' ? ' tab-btn-active' : ''}`}
                    onClick={() => setActiveComponent('dashboard')}
                    role="tab"
                    aria-controls="dashboard-panel"
                    aria-label="Dashboard"
                    title="Dashboard"
                    style={{ 
                      fontSize: '1.2em', 
                      padding: '0.3em', 
                      width: '40px', 
                      height: '40px',
                      borderRadius: '8px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}
                  >
                    <span role="img" aria-label="Dashboard">🏠</span>
                  </button>
                  <button
                    className={`tab-btn${activeComponent === 'profile' ? ' tab-btn-active' : ''}`}
                    onClick={() => setActiveComponent('profile')}
                    role="tab"
                    aria-controls="profile-panel"
                    aria-label="Profile"
                    title="Profile"
                    style={{ 
                      fontSize: '1.2em', 
                      padding: '0.3em', 
                      width: '40px', 
                      height: '40px',
                      borderRadius: '8px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}
                  >
                    <span role="img" aria-label="Profile">👤</span>
                  </button>
                  <button
                    className={`tab-btn${activeComponent === 'keys' ? ' tab-btn-active' : ''}`}
                    onClick={() => setActiveComponent('keys')}
                    role="tab"
                    aria-controls="keys-panel"
                    aria-label="Keys"
                    title="Keys"
                    style={{ 
                      fontSize: '1.2em', 
                      padding: '0.3em', 
                      width: '40px', 
                      height: '40px',
                      borderRadius: '8px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}
                  >
                    <span role="img" aria-label="Keys">🔑</span>
                  </button>
                  <button
                    className={`tab-btn${activeComponent === 'backup' ? ' tab-btn-active' : ''}`}
                    onClick={() => setActiveComponent('backup')}
                    role="tab"
                    aria-controls="backup-panel"
                    aria-label="Backup"
                    title="Backup"
                    style={{ 
                      fontSize: '1.2em', 
                      padding: '0.3em', 
                      width: '40px', 
                      height: '40px',
                      borderRadius: '8px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}
                  >
                    <span role="img" aria-label="Backup">💾</span>
                  </button>
                </div>
                <button
                  className="logout-btn"
                  onClick={handleLogout}
                  aria-label="Logout"
                  title="Logout"
                  style={{ 
                    fontSize: '1.2em', 
                    padding: '0.3em', 
                    width: '40px', 
                    height: '40px',
                    borderRadius: '8px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}
                >
                  <span role="img" aria-label="Logout">⏻</span>
                </button>
              </div>
            </nav>
            <main role="main" aria-label="Application content">
              <div
                 role="tabpanel"
                 id="dashboard-panel"
                 aria-labelledby="dashboard-tab"
                 style={{ display: activeComponent === 'dashboard' ? 'block' : 'none' }}
               >
                 {activeComponent === 'dashboard' && <Dashboard jwt={jwt} />}
               </div>
               <div
                 role="tabpanel"
                 id="profile-panel"
                 aria-labelledby="profile-tab"
                 style={{ display: activeComponent === 'profile' ? 'block' : 'none' }}
               >
                 {activeComponent === 'profile' && <Profile />}
               </div>
               <div
                 role="tabpanel"
                 id="keys-panel"
                 aria-labelledby="keys-tab"
                 style={{ display: activeComponent === 'keys' ? 'block' : 'none' }}
               >
                 {activeComponent === 'keys' && <KeyManagement showToast={showToast} />}
               </div>
               <div
                 role="tabpanel"
                 id="backup-panel"
                 aria-labelledby="backup-tab"
                 style={{ display: activeComponent === 'backup' ? 'block' : 'none' }}
               >
                 {activeComponent === 'backup' && <BackupKeyManagement showToast={showToast} />}
               </div>
            </main>
          </>
        )}

        <footer role="contentinfo" style={{ textAlign: 'center', marginTop: 32, color: '#bdbdbd', fontSize: '0.95em' }}>
          <p>&copy; {new Date().getFullYear()} ECC Passwordless MFA</p>
        </footer>
      </div>

      <button
        className="theme-toggle-btn"
        aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
        title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
      >
        <span aria-hidden="true">{theme === 'dark' ? '🌞' : '🌙'}</span>
      </button>

      {showLogoutModal && (
        <div 
          className="modal-overlay"
          role="presentation"
          aria-hidden="true"
        >
          <div
            className="modal-content slide-down-in"
            role="dialog"
            aria-modal="true"
            aria-labelledby="logout-modal-title"
            aria-describedby="logout-modal-description"
            ref={modalRef}
          >
            <h2 id="logout-modal-title" style={{ marginTop: 0, marginBottom: 12 }}>Confirm Logout</h2>
            <div id="logout-modal-description" style={{ fontSize: '1.05em', marginBottom: 18 }}>
              <p>
                Logging out will remove your authentication token.<br />
                <strong>You will need to re-authenticate to access the dashboard and key management.</strong><br />
                Your device key will remain unless you remove it from Key Management.
              </p>
            </div>
            <div role="group" aria-label="Logout confirmation actions">
              <button 
                onClick={confirmLogout} 
                style={{ marginRight: 12 }} 
                aria-label="Confirm logout and return to authentication"
              >
                Confirm Logout
              </button>
              <button 
                onClick={cancelLogout} 
                style={{ background: '#3a506b' }} 
                aria-label="Cancel logout and stay logged in"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {toast && (
        <Toast 
          message={toast.message} 
          type={toast.type} 
          onClose={() => setToast(null)} 
          className="slide-down-in" 
        />
      )}
    </>
  );
};

export default App;