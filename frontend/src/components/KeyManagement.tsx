import React, { useState, useEffect } from 'react';
import { loadPrivateKey, savePrivateKey } from '../services/storage';
import { exportPublicKey, generateKeyPair } from '../services/crypto';
import { getDevices, addDevice, removeDevice, getDevicePublicKey } from '../services/api';
import { generateDeviceName, detectDeviceInfo, getDetailedDeviceInfo } from '../utils/deviceDetection';

interface Device {
  device_id: string;
  device_name: string;
  created_at: string | null;
  last_used: string | null;
  is_active: boolean;
}

interface KeyManagementProps {
  showToast?: (message: string, type: 'success' | 'error' | 'info') => void;
}

const KeyManagement: React.FC<KeyManagementProps> = ({ showToast }) => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newDeviceName, setNewDeviceName] = useState('');
  const [detectedDeviceInfo, setDetectedDeviceInfo] = useState<string>('');
  const [addingDevice, setAddingDevice] = useState(false);
  const [removingDevice, setRemovingDevice] = useState<string | null>(null);
  const [currentDevicePublicKey, setCurrentDevicePublicKey] = useState<string>('');
  const [loadingPublicKey, setLoadingPublicKey] = useState(false);
  
  // New state for pagination and search
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [removingAll, setRemovingAll] = useState(false);
  const [currentDeviceId, setCurrentDeviceId] = useState<string | null>(null);
  const devicesPerPage = 3;

  useEffect(() => {
    loadDevices();
    // Auto-detect device name for new device form
    try {
      const deviceInfo = detectDeviceInfo();
      const autoDeviceName = generateDeviceName(deviceInfo);
      setNewDeviceName(autoDeviceName);
      setDetectedDeviceInfo(getDetailedDeviceInfo());
    } catch (err) {
      console.warn('Failed to auto-detect device:', err);
      setNewDeviceName('Unknown Device');
      setDetectedDeviceInfo('Device detection failed');
    }
    
    // Get current device ID from JWT token
    const token = localStorage.getItem('jwt');
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        setCurrentDeviceId(payload.device_id);
      } catch (err) {
        console.warn('Failed to decode JWT token:', err);
      }
    }
  }, []);

  // Load public key when devices are loaded
  useEffect(() => {
    if (devices.length > 0) {
      loadCurrentDevicePublicKey();
    }
  }, [devices]);

  const loadCurrentDevicePublicKey = async () => {
    if (devices.length === 0) return;
    
    setLoadingPublicKey(true);
    try {
      const response = await getDevicePublicKey(devices[0].device_id);
      setCurrentDevicePublicKey(response.public_key_pem);
    } catch (err: any) {
      console.warn('Failed to load public key:', err);
      setCurrentDevicePublicKey('Failed to load public key');
    } finally {
      setLoadingPublicKey(false);
    }
  };

  const handleCopyPublicKey = async () => {
    if (!currentDevicePublicKey || currentDevicePublicKey === 'Failed to load public key') {
      showToast?.('No public key available to copy', 'error');
      return;
    }
    
    try {
      await navigator.clipboard.writeText(currentDevicePublicKey);
      showToast?.('Public key copied to clipboard!', 'success');
    } catch (err: any) {
      showToast?.('Failed to copy public key: ' + (err?.message || err), 'error');
    }
  };

  const loadDevices = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await getDevices();
      setDevices(response.devices);
    } catch (err: any) {
      setError(err.message || 'Failed to load devices');
      showToast?.('Failed to load devices', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleAddDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDeviceName.trim()) {
      showToast?.('Please enter a device name', 'error');
      return;
    }

    try {
      setAddingDevice(true);
      setError(null);
      
      // Generate new key pair
      const keyPair = await generateKeyPair();
      const publicKeyPem = await exportPublicKey(keyPair.publicKey);
      
      // Save private key to local storage
      await savePrivateKey(keyPair.privateKey);
      
      // Register device with backend
      await addDevice(publicKeyPem, newDeviceName.trim());
      
      showToast?.('New device added successfully!', 'success');
      setNewDeviceName('');
      loadDevices(); // Refresh device list
    } catch (err: any) {
      setError(err.message || 'Failed to add device');
      showToast?.('Failed to add device', 'error');
    } finally {
      setAddingDevice(false);
    }
  };

  const handleRemoveDevice = async (deviceId: string) => {
    // Get the current device ID from JWT token
    const token = localStorage.getItem('jwt');
    if (!token) {
      showToast?.('No authentication token found', 'error');
      return;
    }
    
    // Decode JWT to get current device ID (without verification for client-side)
    const payload = JSON.parse(atob(token.split('.')[1]));
    const currentDeviceId = payload.device_id;
    
    if (deviceId === currentDeviceId) {
      showToast?.('You cannot remove your current device. This would lock you out of your account.', 'error');
      return;
    }
    
    if (!window.confirm('Are you sure you want to remove this device? This action cannot be undone.')) {
      return;
    }

    try {
      setRemovingDevice(deviceId);
      setError(null);
      await removeDevice(deviceId);
      showToast?.('Device removed successfully!', 'success');
      loadDevices(); // Refresh device list
    } catch (err: any) {
      setError(err.message || 'Failed to remove device');
      showToast?.('Failed to remove device', 'error');
    } finally {
      setRemovingDevice(null);
    }
  };

  const handleRemoveAllDevices = async () => {
    if (!window.confirm('Are you sure you want to remove ALL devices? This action cannot be undone and you will lose access to your account.')) {
      return;
    }

    try {
      setRemovingAll(true);
      setError(null);
      
      // Get the current device ID from JWT token
      const token = localStorage.getItem('jwt');
      if (!token) {
        throw new Error('No authentication token found');
      }
      
      // Decode JWT to get current device ID (without verification for client-side)
      const payload = JSON.parse(atob(token.split('.')[1]));
      const currentDeviceId = payload.device_id;
      
      if (!currentDeviceId) {
        throw new Error('Current device ID not found in token');
      }
      
      // Remove all devices except the current one
      const devicesToRemove = devices.filter(device => device.device_id !== currentDeviceId);
      
      if (devicesToRemove.length === 0) {
        showToast?.('No other devices to remove. You cannot remove your current device.', 'info');
        return;
      }
      
      for (const device of devicesToRemove) {
        await removeDevice(device.device_id);
      }
      
      showToast?.(`Removed ${devicesToRemove.length} device(s) successfully! Your current device is protected.`, 'success');
      loadDevices(); // Refresh device list
    } catch (err: any) {
      setError(err.message || 'Failed to remove all devices');
      showToast?.('Failed to remove all devices', 'error');
    } finally {
      setRemovingAll(false);
    }
  };

  // Filter devices based on search term
  const filteredDevices = devices.filter(device =>
    device.device_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    device.device_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Calculate pagination
  const totalPages = Math.ceil(filteredDevices.length / devicesPerPage);
  const startIndex = (currentPage - 1) * devicesPerPage;
  const endIndex = startIndex + devicesPerPage;
  const currentDevices = filteredDevices.slice(startIndex, endIndex);

  // Reset to first page when search changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm]);

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  if (loading) {
    return (
      <div style={{ 
        textAlign: 'center', 
        padding: '2rem',
        color: 'var(--color-main)'
      }}>
        <div style={{ 
          fontSize: '1.2em',
          marginBottom: '1rem'
        }}>
          Loading devices...
        </div>
      </div>
    );
  }

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
        Device Management
      </h2>
      
      <p style={{ 
        marginBottom: '2rem',
        color: 'var(--color-main)',
        opacity: 0.8
      }}>
        Manage your registered devices. Each device has its own cryptographic key pair for secure authentication.
      </p>

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

      <div className="current-device-section">
        <h3 style={{ 
          marginBottom: '1rem',
          fontSize: '1.3em',
          fontWeight: '600',
          color: 'var(--color-main)'
        }}>
          Current Device Public Key
        </h3>
        <p style={{ 
          marginBottom: '1rem',
          color: 'var(--color-main)',
          opacity: 0.8
        }}>
          This is the public key for your current device. You can copy it for backup or verification purposes.
        </p>
        <div style={{
          border: '1px solid var(--color-border)',
          borderRadius: '8px',
          padding: '12px',
          background: 'var(--bg-card)',
          marginBottom: '16px'
        }}>
          {loadingPublicKey ? (
            <div style={{ 
              color: 'var(--color-main)',
              opacity: 0.6,
              fontStyle: 'italic'
            }}>
              Loading public key...
            </div>
          ) : currentDevicePublicKey ? (
            <>
              <div style={{ 
                fontFamily: 'monospace', 
                fontSize: '0.85em', 
                color: 'var(--color-code)',
                wordBreak: 'break-all',
                whiteSpace: 'pre-wrap',
                marginBottom: '12px',
                maxHeight: '300px',
                overflowY: 'auto',
                background: 'var(--color-code-bg)',
                padding: '16px',
                borderRadius: '6px',
                lineHeight: '1.4',
                border: '1px solid var(--color-border)'
              }}>
                {currentDevicePublicKey}
              </div>
              <button
                onClick={handleCopyPublicKey}
                style={{
                  background: 'var(--color-accent)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '8px 16px',
                  fontSize: '0.9em',
                  cursor: 'pointer',
                  fontWeight: '500'
                }}
              >
                Copy Public Key
              </button>
            </>
          ) : (
            <div style={{ 
              color: 'var(--color-main)',
              opacity: 0.6,
              fontStyle: 'italic'
            }}>
              No public key available
            </div>
          )}
        </div>
      </div>

      <hr style={{ 
        margin: '24px 0',
        border: 'none',
        borderTop: '1px solid var(--color-border)'
      }} />

      <div className="add-device-section">
        <h3 style={{ 
          marginBottom: '1rem',
          fontSize: '1.3em',
          fontWeight: '600',
          color: 'var(--color-main)'
        }}>
          Add New Device
        </h3>
        <p style={{ 
          marginBottom: '1rem',
          color: 'var(--color-main)',
          opacity: 0.8
        }}>
          Generate a new key pair for another device (e.g., phone, tablet, work computer).
        </p>
        <form onSubmit={handleAddDevice} style={{ marginBottom: '1rem' }}>
          <label htmlFor="new-device-name" style={{ 
            display: 'block', 
            marginBottom: 6, 
            fontWeight: 500,
            color: 'var(--color-main)',
            fontSize: '0.9em'
          }}>
            Device Name
          </label>
          <div style={{ 
            display: 'flex', 
            gap: 12, 
            alignItems: 'stretch'
          }}>
        <input
              id="new-device-name"
              type="text"
              placeholder="e.g., iPhone 14, Work Laptop"
              value={newDeviceName}
              onChange={(e) => setNewDeviceName(e.target.value)}
              disabled={addingDevice}
              style={{
                flex: '1',
                padding: '12px 16px',
                borderRadius: 8,
                border: '1px solid var(--color-border)',
                background: 'var(--bg-card)',
                color: 'var(--color-main)',
                fontSize: '1em',
                minHeight: '44px',
                boxSizing: 'border-box'
              }}
            />
            <button
              type="submit"
              disabled={addingDevice || !newDeviceName.trim()}
              style={{
                background: addingDevice || !newDeviceName.trim() ? 'var(--color-border)' : 'var(--color-accent)',
                color: '#fff',
                border: 'none',
                borderRadius: 8,
                padding: '12px 20px',
                fontWeight: 600,
                fontSize: '0.95em',
                cursor: addingDevice || !newDeviceName.trim() ? 'not-allowed' : 'pointer',
                minHeight: '44px',
                whiteSpace: 'nowrap',
                transition: 'all 0.2s ease',
                minWidth: '120px'
              }}
            >
              {addingDevice ? 'Adding...' : 'Add Device'}
            </button>
          </div>
          {detectedDeviceInfo && (
            <div style={{ 
              fontSize: '0.8em', 
              color: 'var(--color-main)',
              opacity: 0.6,
              fontStyle: 'italic',
              marginTop: 8,
              marginLeft: 2
            }}>
              <span aria-hidden="true">🔍</span> Detected: {detectedDeviceInfo}
            </div>
          )}
        </form>
      </div>

      <hr style={{ 
        margin: '24px 0',
        border: 'none',
        borderTop: '1px solid var(--color-border)'
      }} />

      <div style={{ marginBottom: '2rem' }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1rem',
          flexWrap: 'wrap',
          gap: '1rem'
        }}>
          <h3 style={{ 
            fontSize: '1.3em',
            fontWeight: '600',
            color: 'var(--color-main)',
            margin: 0
          }}>
            Your Devices ({filteredDevices.length})
          </h3>
          
          {devices.length > 2 && (
            <button
              onClick={handleRemoveAllDevices}
              disabled={removingAll}
              style={{
                background: removingAll ? 'var(--color-border)' : '#ff1744',
                color: '#fff',
                border: 'none',
                borderRadius: '8px',
                padding: '8px 16px',
                fontSize: '0.9em',
                cursor: removingAll ? 'not-allowed' : 'pointer',
                fontWeight: '500',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
              aria-label="Remove all devices"
            >
              <span role="img" aria-hidden="true">🗑️</span>
              {removingAll ? 'Removing...' : 'Remove All'}
            </button>
          )}
        </div>

        {/* Search Bar */}
        <div style={{ marginBottom: '1rem' }}>
          <input
            type="text"
            placeholder="Search devices by name or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '12px 16px',
              borderRadius: 8,
              border: '1px solid var(--color-border)',
              background: 'var(--bg-card)',
              color: 'var(--color-main)',
              fontSize: '1em',
              minHeight: '44px',
              boxSizing: 'border-box'
            }}
          />
        </div>
        
        {filteredDevices.length === 0 ? (
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--color-border)',
            borderRadius: '12px',
            padding: '2rem',
            textAlign: 'center',
            color: 'var(--color-main)',
            opacity: 0.7
          }}>
            <div style={{ fontSize: '1.1em', marginBottom: '0.5rem' }}>
              {searchTerm ? 'No devices found matching your search' : 'No devices found'}
            </div>
            <div style={{ fontSize: '0.9em' }}>
              {searchTerm ? 'Try adjusting your search terms.' : 'Add your first device to get started with passwordless authentication.'}
            </div>
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {currentDevices.map((device) => (
                <div
                  key={device.device_id}
                  style={{
                    background: device.device_id === currentDeviceId ? 'var(--color-accent)' : 'var(--bg-card)',
                    border: `1px solid ${device.device_id === currentDeviceId ? 'var(--color-accent)' : 'var(--color-border)'}`,
                    borderRadius: '12px',
                    padding: '1.5rem',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    boxShadow: '0 2px 8px var(--color-shadow)',
                    position: 'relative'
                  }}
                >
                  {device.device_id === currentDeviceId && (
                    <div style={{
                      position: 'absolute',
                      top: '8px',
                      right: '8px',
                      background: '#fff',
                      color: 'var(--color-accent)',
                      padding: '2px 8px',
                      borderRadius: '12px',
                      fontSize: '0.7em',
                      fontWeight: '600'
                    }}>
                      Current
                    </div>
                  )}
                  <div style={{ flex: 1 }}>
                    <div style={{ 
                      fontSize: '1.1em',
                      fontWeight: '600',
                      marginBottom: '0.5rem',
                      color: device.device_id === currentDeviceId ? '#fff' : 'var(--color-main)'
                    }}>
                      {device.device_name}
                    </div>
                    <div style={{ 
                      fontSize: '0.9em',
                      color: device.device_id === currentDeviceId ? '#fff' : 'var(--color-main)',
                      opacity: device.device_id === currentDeviceId ? 0.9 : 0.7
                    }}>
                      <div>Device ID: {device.device_id.substring(0, 8)}...</div>
                      <div>Created: {formatDate(device.created_at)}</div>
                      <div>Last Used: {formatDate(device.last_used)}</div>
                      <div>Status: {device.is_active ? 'Active' : 'Inactive'}</div>
                    </div>
                  </div>
                  <button
                    onClick={() => handleRemoveDevice(device.device_id)}
                    disabled={removingDevice === device.device_id || device.device_id === currentDeviceId}
                    style={{
                      background: device.device_id === currentDeviceId ? 'var(--color-border)' : 
                                removingDevice === device.device_id ? 'var(--color-border)' : '#ff1744',
                      color: '#fff',
                      border: 'none',
                      borderRadius: '8px',
                      padding: '8px 12px',
                      fontSize: '0.9em',
                      cursor: device.device_id === currentDeviceId || removingDevice === device.device_id ? 'not-allowed' : 'pointer',
                      fontWeight: '500',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      minWidth: '44px',
                      justifyContent: 'center',
                      opacity: device.device_id === currentDeviceId ? 0.5 : 1
                    }}
                    aria-label={device.device_id === currentDeviceId ? 
                      `Cannot remove current device ${device.device_name}` : 
                      `Remove device ${device.device_name}`}
                  >
                    <span role="img" aria-hidden="true">🗑️</span>
                    {removingDevice === device.device_id ? '...' : ''}
                  </button>
                </div>
              ))}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                gap: '0.5rem',
                marginTop: '1.5rem',
                flexWrap: 'wrap'
              }}>
                <button
                  onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                  disabled={currentPage === 1}
                  style={{
                    background: currentPage === 1 ? 'var(--color-border)' : 'var(--color-accent)',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '8px 12px',
                    fontSize: '0.9em',
                    cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                    fontWeight: '500'
                  }}
                  aria-label="Previous page"
                >
                  ←
                </button>
                
                {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                  <button
                    key={page}
                    onClick={() => setCurrentPage(page)}
                    style={{
                      background: currentPage === page ? 'var(--color-accent)' : 'var(--bg-card)',
                      color: currentPage === page ? '#fff' : 'var(--color-main)',
                      border: `1px solid ${currentPage === page ? 'var(--color-accent)' : 'var(--color-border)'}`,
                      borderRadius: '6px',
                      padding: '8px 12px',
                      fontSize: '0.9em',
                      cursor: 'pointer',
                      fontWeight: '500',
                      minWidth: '40px'
                    }}
                    aria-label={`Page ${page}`}
                    aria-current={currentPage === page ? 'page' : undefined}
                  >
                    {page}
                  </button>
                ))}
                
                <button
                  onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                  disabled={currentPage === totalPages}
                  style={{
                    background: currentPage === totalPages ? 'var(--color-border)' : 'var(--color-accent)',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '8px 12px',
                    fontSize: '0.9em',
                    cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                    fontWeight: '500'
                  }}
                  aria-label="Next page"
                >
                  →
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default KeyManagement; 