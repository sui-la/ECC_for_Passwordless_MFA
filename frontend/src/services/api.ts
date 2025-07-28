const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

export async function register(email: string, publicKeyPem: string, deviceName?: string) {
  const res = await fetch(`${API_URL}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      email, 
      public_key_pem: publicKeyPem,
      device_name: deviceName || 'Unknown Device'
    })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Registration failed');
  return res.json();
}

export async function getChallenge(email: string): Promise<{ nonce: string }> {
  const res = await fetch(`${API_URL}/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Challenge request failed');
  return res.json();
}

export async function verify(email: string, signature: string): Promise<{ token: string; server_ecdh_public_key: string }> {
  
  const res = await fetch(`${API_URL}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, signature })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Verification failed');
  return res.json();
}

export async function getProfile(): Promise<{ email: string; last_login: string | null; created_at: string | null }> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  
  const res = await fetch(`${API_URL}/profile`, {
    method: 'GET',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to fetch profile');
  return res.json();
} 

export async function sendECDHPublicKey(clientECDHPublicKeyPem: string): Promise<{ message: string }> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  const res = await fetch(`${API_URL}/session/ecdh`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ client_ecdh_public_key: clientECDHPublicKeyPem })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'ECDH key exchange failed');
  return res.json();
} 

export async function sendSecureData(ciphertext: string, iv: string): Promise<{ ciphertext: string, iv: string }> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  const res = await fetch(`${API_URL}/session/secure-data`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ ciphertext, iv })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Secure data exchange failed');
  return res.json();
} 

export async function getDevices(): Promise<{ devices: Array<{
  device_id: string;
  device_name: string;
  created_at: string | null;
  last_used: string | null;
  is_active: boolean;
}> }> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  
  const res = await fetch(`${API_URL}/devices`, {
    method: 'GET',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to fetch devices');
  return res.json();
}

export async function addDevice(publicKeyPem: string, deviceName: string): Promise<{
  message: string;
  device_id: string;
  device_name: string;
}> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  
  const res = await fetch(`${API_URL}/devices`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ 
      public_key_pem: publicKeyPem,
      device_name: deviceName
    })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to add device');
  return res.json();
}

export async function removeDevice(deviceId: string): Promise<{ message: string }> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  
  const res = await fetch(`${API_URL}/devices/${deviceId}`, {
    method: 'DELETE',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to remove device');
  return res.json();
} 

export async function getDevicePublicKey(deviceId: string): Promise<{
  device_id: string;
  device_name: string;
  public_key_pem: string;
}> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  
  const res = await fetch(`${API_URL}/devices/${deviceId}/public-key`, {
    method: 'GET',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to get device public key');
  return res.json();
} 

export async function initiateRecovery(email: string): Promise<{ message: string }> {
  const res = await fetch(`${API_URL}/recovery/initiate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to initiate recovery');
  return res.json();
}

export async function verifyRecoveryToken(recoveryToken: string): Promise<{
  email: string;
  user_id: string;
  recovery_token: string;
}> {
  const res = await fetch(`${API_URL}/recovery/verify-token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recovery_token: recoveryToken })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to verify recovery token');
  return res.json();
}

export async function completeRecovery(
  recoveryToken: string, 
  publicKeyPem: string, 
  deviceName: string
): Promise<{ message: string }> {
  const res = await fetch(`${API_URL}/recovery/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      recovery_token: recoveryToken,
      public_key_pem: publicKeyPem,
      device_name: deviceName
    })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to complete recovery');
  return res.json();
}

export async function generateBackupKey(): Promise<{
  private_key_pem: string;
  public_key_pem: string;
  backup_id: string;
  created_at: string;
}> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  
  const res = await fetch(`${API_URL}/backup/generate`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to generate backup key');
  return res.json();
} 