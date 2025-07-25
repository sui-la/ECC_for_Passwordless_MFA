const DB_NAME = 'ecc-mfa-db';
const STORE_NAME = 'keys';
const KEY_ID = 'privateKey';

export async function savePrivateKey(key: CryptoKey) {
  // Export the key as JWK for storage
  const jwk = await window.crypto.subtle.exportKey('jwk', key);
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  tx.objectStore(STORE_NAME).put(jwk, KEY_ID);
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