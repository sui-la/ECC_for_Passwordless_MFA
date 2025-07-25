const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

export async function register(email: string, publicKeyPem: string) {
  const res = await fetch(`${API_URL}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, public_key_pem: publicKeyPem })
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