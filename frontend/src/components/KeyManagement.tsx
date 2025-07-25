import React, { useEffect, useState } from 'react';
import { loadPrivateKey, savePrivateKey } from '../services/storage';
import { exportPublicKey, generateKeyPair } from '../services/crypto';
import { register } from '../services/api';

interface KeyManagementProps {
  showToast: (message: string, type?: 'success' | 'error' | 'info') => void;
}

const KeyManagement: React.FC<KeyManagementProps> = ({ showToast }) => {
  const [publicKeyPem, setPublicKeyPem] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    (async () => {
      const privateKey = await loadPrivateKey();
      if (privateKey) {
        const keyPair = await generateKeyPair();
        const pubKey = await exportPublicKey(keyPair.publicKey);
        setPublicKeyPem(pubKey);
      } else {
        setPublicKeyPem(null);
      }
    })();
  }, []);

  const handleRemove = async () => {
    const db = await (window as any).indexedDB.open('ecc-mfa-db', 1);
    db.onsuccess = () => {
      const database = db.result;
      const tx = database.transaction('keys', 'readwrite');
      tx.objectStore('keys').delete('privateKey');
      tx.oncomplete = () => {
        setPublicKeyPem(null);
        showToast('Device key removed.', 'success');
      };
    };
  };

  const handleReregister = async () => {
    if (!email) {
      showToast('Enter your email to re-register.', 'info');
      return;
    }
    try {
      const { privateKey, publicKey } = await generateKeyPair();
      await savePrivateKey(privateKey);
      const pubKeyPem = await exportPublicKey(publicKey);
      const resp = await register(email, pubKeyPem);
      setPublicKeyPem(pubKeyPem);
      showToast(resp.message || 'Device re-registered successfully!', 'success');
    } catch (err: any) {
      showToast('Re-registration failed: ' + (err?.message || err), 'error');
    }
  };

  const handleCopy = () => {
    if (publicKeyPem) {
      navigator.clipboard.writeText(publicKeyPem);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
      showToast('Public key copied!', 'info');
    }
  };

  return (
    <div className="section">
      <h2>Key Management</h2>
      {publicKeyPem ? (
        <div>
          <h4>Current Device Public Key</h4>
          <div className="public-key-block">
            {publicKeyPem}
            <button className="copy-btn" onClick={handleCopy}>{copied ? 'Copied!' : 'Copy'}</button>
          </div>
          <button onClick={handleRemove}>Remove Device</button>
        </div>
      ) : (
        <div className="alert alert-info">No device key found.</div>
      )}
      <div style={{ marginTop: 10 }}>
        <input
          type="email"
          placeholder="Email for re-registration"
          value={email}
          onChange={e => setEmail(e.target.value)}
        />
        <button onClick={handleReregister}>Re-register Device</button>
      </div>
    </div>
  );
};

export default KeyManagement; 