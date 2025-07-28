export async function generateKeyPair() {
  return window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );
}

export async function signMessage(privateKey: CryptoKey, message: string | ArrayBufferLike): Promise<string> {
  let data: Uint8Array;
  if (typeof message === 'string') {
    data = new TextEncoder().encode(message);
  } else {
    data = new Uint8Array(message);
  }
  const signature = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  );
  return window.btoa(String.fromCharCode(...new Uint8Array(signature)));
}

export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const spki = await window.crypto.subtle.exportKey('spki', publicKey);
  const b64 = window.btoa(String.fromCharCode(...new Uint8Array(spki)));
  const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;
  return pem;
}

export async function generateECDHKeyPair() {
  return window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
}

export async function exportECDHPublicKey(publicKey: CryptoKey): Promise<string> {
  const spki = await window.crypto.subtle.exportKey('spki', publicKey);
  const b64 = window.btoa(String.fromCharCode(...new Uint8Array(spki)));
  const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;
  return pem;
}

export async function importECDHPublicKey(pem: string): Promise<CryptoKey> {
  const b64 = pem.replace(/-----[^-]+-----|\s+/g, '');
  const binary = Uint8Array.from(window.atob(b64), c => c.charCodeAt(0));
  return window.crypto.subtle.importKey(
    'spki',
    binary,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
}

export async function deriveSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<ArrayBuffer> {
  return window.crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: publicKey,
    },
    privateKey,
    256
  );
}

export async function importAesKeyFromSharedSecret(sharedSecret: ArrayBuffer): Promise<CryptoKey> {
  // Use HKDF or SHA-256 to derive a 256-bit AES key from the shared secret
  const hash = await window.crypto.subtle.digest('SHA-256', sharedSecret);
  return window.crypto.subtle.importKey(
    'raw',
    hash,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function aesGcmEncrypt(plaintext: string, key: CryptoKey): Promise<{ ciphertext: string, iv: string }> {
  const enc = new TextEncoder();
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const ciphertextBuf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(plaintext)
  );
  return {
    ciphertext: window.btoa(String.fromCharCode(...new Uint8Array(ciphertextBuf))),
    iv: window.btoa(String.fromCharCode(...iv))
  };
}

export async function aesGcmDecrypt(ciphertext: string, iv: string, key: CryptoKey): Promise<string> {
  const dec = new TextDecoder();
  const ciphertextBuf = Uint8Array.from(window.atob(ciphertext), c => c.charCodeAt(0));
  const ivBuf = Uint8Array.from(window.atob(iv), c => c.charCodeAt(0));
  const plaintextBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuf },
    key,
    ciphertextBuf
  );
  return dec.decode(plaintextBuf);
} 