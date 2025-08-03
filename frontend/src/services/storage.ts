const DB_NAME = 'ecc-mfa-db';
const STORE_NAME = 'keys';
const KEY_ID = 'privateKey';
const DEVICE_ID_KEY = 'deviceId';

export async function savePrivateKey(key: CryptoKey, deviceId?: string) {
  // Export the key as JWK for storage
  const jwk = await window.crypto.subtle.exportKey('jwk', key);
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  tx.objectStore(STORE_NAME).put(jwk, KEY_ID);
  
  // Also store the device ID if provided
  if (deviceId) {
    tx.objectStore(STORE_NAME).put(deviceId, DEVICE_ID_KEY);
  }
  
  await new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = reject;
  });
  db.close();
}

export async function loadPrivateKey(): Promise<CryptoKey | null> {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readonly');
  const req = tx.objectStore(STORE_NAME).get(KEY_ID);
  const jwk = await new Promise<any>((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  db.close();
  if (!jwk) return null;
  return window.crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );
}

export async function getDeviceId(): Promise<string | null> {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readonly');
  const req = tx.objectStore(STORE_NAME).get(DEVICE_ID_KEY);
  const deviceId = await new Promise<any>((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  db.close();
  return deviceId || null;
}

const SESSION_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds (matching backend)

export function isSessionExpired(): boolean {
  try {
    const sessionStart = localStorage.getItem('sessionStartTime');
    if (!sessionStart) return true;
    
    const now = Date.now();
    const sessionAge = now - parseInt(sessionStart);
    return sessionAge > SESSION_DURATION;
  } catch (error) {
    console.error('Error checking session expiry:', error);
    return true; // Assume expired if we can't check
  }
}

export async function saveSessionSharedSecret(sharedSecret: ArrayBuffer): Promise<void> {
  try {
    // Convert ArrayBuffer to base64 string for storage
    const uint8Array = new Uint8Array(sharedSecret);
    const base64String = btoa(String.fromCharCode(...uint8Array));
    localStorage.setItem('sessionSharedSecret', base64String);
    localStorage.setItem('sessionStartTime', Date.now().toString());
  } catch (error) {
    console.error('Failed to save session shared secret:', error);
    throw new Error('Failed to save session shared secret');
  }
}

export async function loadSessionSharedSecret(): Promise<ArrayBuffer | null> {
  try {
    // Check if session is expired
    if (isSessionExpired()) {
      await clearSessionSharedSecret();
      return null;
    }

    const base64String = localStorage.getItem('sessionSharedSecret');
    if (!base64String) {
      return null;
    }
    
    // Convert base64 string back to ArrayBuffer
    const binaryString = atob(base64String);
    const uint8Array = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      uint8Array[i] = binaryString.charCodeAt(i);
    }
    
    const result = uint8Array.buffer;
    return result;
  } catch (error) {
    console.error('❌ Failed to load session shared secret:', error);
    return null;
  }
}

export async function clearSessionSharedSecret(): Promise<void> {
  try {
    localStorage.removeItem('sessionSharedSecret');
    localStorage.removeItem('sessionStartTime');
  } catch (error) {
    console.error('Failed to clear session shared secret:', error);
  }
}

export async function getValidSessionSecret(): Promise<ArrayBuffer | null> {
  try {
    // First try to load from localStorage
    let sharedSecret = await loadSessionSharedSecret();
    
    if (!sharedSecret) {
      return null;
    }
    
    return sharedSecret;
  } catch (error) {
    console.error('❌ Error getting valid session secret:', error);
    return null;
  }
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = window.indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE_NAME);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
} 