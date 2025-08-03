const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

export async function register(email: string, publicKeyPem: string, deviceName?: string): Promise<{ message: string; device_id?: string }> {
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

export async function verify(email: string, signature: string, deviceId?: string): Promise<{ token: string; server_ecdh_public_key: string } | { requires_verification: true; error: string; message: string }> {
  const body: any = { email, signature };
  if (deviceId) {
    body.device_id = deviceId;
  }
  
  const res = await fetch(`${API_URL}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  
  const responseData = await res.json();
  
  // Handle email verification requirement specially
  if (res.status === 403 && responseData.requires_verification) {
    return responseData;
  }
  
  if (!res.ok) {
    throw new Error(responseData.error || 'Verification failed');
  }
  
  return responseData;
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

export async function sendSecureMessage(recipientEmail: string, encryptedMessage: string, messageIv: string, messageId: string): Promise<{ message: string, message_id: string }> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  const res = await fetch(`${API_URL}/session/send-secure-message`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ 
      recipient_email: recipientEmail, 
      encrypted_message: encryptedMessage, 
      message_iv: messageIv,
      message_id: messageId
    })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to send secure message');
  return res.json();
}

export async function receiveSecureMessages(): Promise<{ messages: Array<{
  message_id: string;
  sender_email: string;
  encrypted_message: string;
  message_iv: string;
  timestamp: string;
  session_id: string;
}>, count: number }> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  const res = await fetch(`${API_URL}/session/receive-secure-messages`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to receive secure messages');
  return res.json();
}

export async function deleteSecureMessage(messageId: string): Promise<{ message: string }> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  const res = await fetch(`${API_URL}/session/delete-secure-message/${messageId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to delete secure message');
  return res.json();
}

export async function updateMessageEncryption(
  messageId: string, 
  encryptedMessage: string, 
  messageIv: string, 
  newMessageId: string
): Promise<{ message: string; new_message_id: string }> {
  const token = localStorage.getItem('jwt');
  if (!token) throw new Error('No authentication token found');
  const res = await fetch(`${API_URL}/session/update-message-encryption/${messageId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      encrypted_message: encryptedMessage,
      message_iv: messageIv,
      new_message_id: newMessageId
    })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to update message encryption');
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
): Promise<{ message: string; device_id: string }> {
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

export async function sendEmailVerification(email: string): Promise<{ message: string }> {
  const res = await fetch(`${API_URL}/email/send-verification`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to send verification code');
  return res.json();
}

export async function verifyEmailCode(email: string, verificationCode: string): Promise<{ message: string }> {
  const res = await fetch(`${API_URL}/email/verify-code`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      email, 
      verification_code: verificationCode 
    })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to verify code');
  return res.json();
}

 