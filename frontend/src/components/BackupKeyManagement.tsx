import React, { useState } from 'react';
import { generateBackupKey } from '../services/api';
import { savePrivateKey } from '../services/storage';

interface BackupKeyManagementProps {
  showToast: (message: string, type: 'success' | 'error' | 'info') => void;
}

const BackupKeyManagement: React.FC<BackupKeyManagementProps> = ({ showToast }) => {
  const [loading, setLoading] = useState(false);
  const [backupKey, setBackupKey] = useState<{
    private_key_pem: string;
    public_key_pem: string;
    backup_id: string;
    created_at: string;
  } | null>(null);
  const [showPrivateKey, setShowPrivateKey] = useState(false);

  const handleGenerateBackupKey = async () => {
    setLoading(true);
    try {
      const backupData = await generateBackupKey();
      setBackupKey(backupData);
      showToast('Backup key generated successfully!', 'success');
    } catch (err: any) {
      showToast(err.message || 'Failed to generate backup key', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveToDevice = async () => {
    if (!backupKey) return;
    
    try {
      // Convert PEM string to ArrayBuffer for Web Crypto API
      const pemString = backupKey.private_key_pem;
      const base64String = pemString
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\s/g, '');
      
      const binaryString = atob(base64String);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      
      // Import the private key and save to device storage
      const privateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        bytes,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
      );
      await savePrivateKey(privateKey);
      showToast('Backup key saved to your device!', 'success');
    } catch (err: any) {
      showToast('Failed to save backup key to device: ' + err.message, 'error');
    }
  };

  const handleDownloadBackup = () => {
    if (!backupKey) return;
    
    const backupData = {
      private_key_pem: backupKey.private_key_pem,
      public_key_pem: backupKey.public_key_pem,
      backup_id: backupKey.backup_id,
      created_at: backupKey.created_at,
      instructions: `
ECC Passwordless MFA - Backup Key

IMPORTANT: Keep this file secure and private. Anyone with access to your private key can authenticate as you.

To restore this backup:
1. Save this file securely
2. Use the private key to authenticate on a new device
3. The public key is already registered with your account

Backup ID: ${backupKey.backup_id}
Created: ${new Date(backupKey.created_at).toLocaleString()}
      `
    };
    
    const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ecc-backup-${backupKey.backup_id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Backup file downloaded!', 'success');
  };

  const handleCopyPrivateKey = async () => {
    if (!backupKey) return;
    
    try {
      await navigator.clipboard.writeText(backupKey.private_key_pem);
      showToast('Private key copied to clipboard!', 'success');
    } catch (err: any) {
      showToast('Failed to copy private key: ' + err.message, 'error');
    }
  };

  const handleCopyPublicKey = async () => {
    if (!backupKey) return;
    
    try {
      await navigator.clipboard.writeText(backupKey.public_key_pem);
      showToast('Public key copied to clipboard!', 'success');
    } catch (err: any) {
      showToast('Failed to copy public key: ' + err.message, 'error');
    }
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
        Backup Key Management
      </h2>
      
      <p style={{ 
        marginBottom: '2rem',
        color: 'var(--color-main)',
        opacity: 0.8
      }}>
        Generate backup keys to recover your account if you lose access to your primary device. 
        Store these keys securely - they provide full access to your account.
      </p>

      {!backupKey && (
        <div style={{ marginBottom: '2rem' }}>
          <button
            onClick={handleGenerateBackupKey}
            disabled={loading}
            style={{
              background: loading ? 'var(--color-border)' : 'var(--color-accent)',
              color: '#fff',
              border: 'none',
              borderRadius: 8,
              padding: '12px 24px',
              fontWeight: 600,
              fontSize: '1em',
              cursor: loading ? 'not-allowed' : 'pointer',
              minHeight: '44px'
            }}
          >
            {loading ? 'Generating...' : 'Generate Backup Key'}
          </button>
        </div>
      )}

      {backupKey && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--color-border)',
          borderRadius: '12px',
          padding: '1.5rem',
          marginBottom: '1rem'
        }}>
          <h3 style={{ 
            marginBottom: '1rem',
            fontSize: '1.3em',
            fontWeight: '600',
            color: 'var(--color-main)'
          }}>
            Backup Key Generated
          </h3>
          
          <div style={{ marginBottom: '1rem' }}>
            <div style={{ 
              fontSize: '0.9em',
              color: 'var(--color-main)',
              opacity: 0.7,
              marginBottom: '0.5rem'
            }}>
              Backup ID: {backupKey.backup_id}
            </div>
            <div style={{ 
              fontSize: '0.9em',
              color: 'var(--color-main)',
              opacity: 0.7
            }}>
              Created: {new Date(backupKey.created_at).toLocaleString()}
            </div>
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ 
              marginBottom: '0.5rem',
              fontSize: '1em',
              fontWeight: '600',
              color: 'var(--color-main)'
            }}>
              Public Key
            </h4>
            <div style={{
              background: 'var(--color-code-bg)',
              border: '1px solid var(--color-border)',
              borderRadius: 6,
              padding: 12,
              fontFamily: 'monospace',
              fontSize: '0.8em',
              color: 'var(--color-code)',
              wordBreak: 'break-all',
              whiteSpace: 'pre-wrap',
              maxHeight: '120px',
              overflowY: 'auto',
              marginBottom: '0.5rem'
            }}>
              {backupKey.public_key_pem}
            </div>
            <button
              onClick={handleCopyPublicKey}
              style={{
                background: 'var(--color-accent)',
                color: '#fff',
                border: 'none',
                borderRadius: 4,
                padding: '4px 8px',
                fontSize: '0.8em',
                cursor: 'pointer'
              }}
            >
              Copy Public Key
            </button>
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center',
              marginBottom: '0.5rem'
            }}>
              <h4 style={{ 
                fontSize: '1em',
                fontWeight: '600',
                color: 'var(--color-main)',
                margin: 0
              }}>
                Private Key
              </h4>
              <button
                onClick={() => setShowPrivateKey(!showPrivateKey)}
                style={{
                  background: 'none',
                  border: '1px solid var(--color-border)',
                  borderRadius: 4,
                  padding: '2px 6px',
                  fontSize: '0.7em',
                  cursor: 'pointer',
                  color: 'var(--color-main)'
                }}
              >
                {showPrivateKey ? 'Hide' : 'Show'}
              </button>
            </div>
            {showPrivateKey && (
              <>
                <div style={{
                  background: 'var(--color-code-bg)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 6,
                  padding: 12,
                  fontFamily: 'monospace',
                  fontSize: '0.8em',
                  color: 'var(--color-code)',
                  wordBreak: 'break-all',
                  whiteSpace: 'pre-wrap',
                  maxHeight: '120px',
                  overflowY: 'auto',
                  marginBottom: '0.5rem'
                }}>
                  {backupKey.private_key_pem}
                </div>
                <button
                  onClick={handleCopyPrivateKey}
                  style={{
                    background: 'var(--color-accent)',
                    color: '#fff',
                    border: 'none',
                    borderRadius: 4,
                    padding: '4px 8px',
                    fontSize: '0.8em',
                    cursor: 'pointer',
                    marginRight: '8px'
                  }}
                >
                  Copy Private Key
                </button>
              </>
            )}
          </div>

          <div style={{ 
            display: 'flex', 
            gap: 8,
            flexWrap: 'wrap'
          }}>
            <button
              onClick={handleSaveToDevice}
              style={{
                background: 'var(--color-accent)',
                color: '#fff',
                border: 'none',
                borderRadius: 6,
                padding: '6px 12px',
                fontWeight: 500,
                fontSize: '0.85em',
                cursor: 'pointer',
                minHeight: '36px'
              }}
            >
              Save to Device
            </button>
            <button
              onClick={handleDownloadBackup}
              style={{
                background: 'var(--color-accent)',
                color: '#fff',
                border: 'none',
                borderRadius: 6,
                padding: '6px 12px',
                fontWeight: 500,
                fontSize: '0.85em',
                cursor: 'pointer',
                minHeight: '36px'
              }}
            >
              Download Backup
            </button>
            <button
              onClick={() => setBackupKey(null)}
              style={{
                background: 'var(--color-border)',
                color: 'var(--color-main)',
                border: 'none',
                borderRadius: 6,
                padding: '6px 12px',
                fontWeight: 500,
                fontSize: '0.85em',
                cursor: 'pointer',
                minHeight: '36px'
              }}
            >
              Generate New Key
            </button>
          </div>
        </div>
      )}

      <div style={{
        background: 'rgba(255, 193, 7, 0.1)',
        border: '1px solid rgba(255, 193, 7, 0.3)',
        borderRadius: 8,
        padding: '1rem',
        marginTop: '1rem'
      }}>
        <h4 style={{ 
          marginBottom: '0.5rem',
          fontSize: '1em',
          fontWeight: '600',
          color: 'var(--color-main)'
        }}>
          ⚠️ Security Warning
        </h4>
        <ul style={{ 
          margin: 0,
          paddingLeft: '1.5rem',
          fontSize: '0.9em',
          color: 'var(--color-main)',
          opacity: 0.8
        }}>
          <li>Keep your backup keys secure and private</li>
          <li>Store them in a safe location (password manager, secure file)</li>
          <li>Anyone with your private key can access your account</li>
          <li>Consider generating multiple backup keys for redundancy</li>
        </ul>
      </div>
    </div>
  );
};

export default BackupKeyManagement; 