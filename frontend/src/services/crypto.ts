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
  
  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    hash,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
  return aesKey;
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
  
  const result = dec.decode(plaintextBuf);
  return result;
} 

// Message-specific key derivation functions
export async function deriveMessageKey(senderEmail: string, recipientEmail: string, messageId: string): Promise<CryptoKey> {
  // Create a deterministic string from sender, recipient, and message ID
  const keyMaterial = `${senderEmail}:${recipientEmail}:${messageId}`;
  
  // Hash the key material to create a consistent key
  const encoder = new TextEncoder();
  const keyData = encoder.encode(keyMaterial);
  const hash = await window.crypto.subtle.digest('SHA-256', keyData);
  
  // Import as AES key
  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    hash,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
  
  return aesKey;
}

export async function aesGcmEncryptWithMessageKey(plaintext: string, senderEmail: string, recipientEmail: string, messageId: string): Promise<{ ciphertext: string, iv: string }> {
  // Derive message-specific key
  const key = await deriveMessageKey(senderEmail, recipientEmail, messageId);
  
  // Encrypt with the message-specific key
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

// Message data validation and fixing functions
export function validateMessageData(encryptedMessage: string, messageIv: string): { isValid: boolean; fixedMessage?: string; fixedIv?: string; error?: string } {
  try {
    // Check if the data looks like base64
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encryptedMessage) || !/^[A-Za-z0-9+/]*={0,2}$/.test(messageIv)) {
      return { isValid: false, error: 'Invalid base64 format' };
    }

    // Decode and check lengths
    const messageBytes = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
    const ivBytes = Uint8Array.from(atob(messageIv), c => c.charCodeAt(0));

    // AES-GCM expects 12-byte IV, but we might have 16-byte IV from old format
    if (ivBytes.length === 16) {
      const fixedIv = ivBytes.slice(0, 12);
      const fixedIvBase64 = btoa(String.fromCharCode(...fixedIv));
      return { isValid: true, fixedMessage: encryptedMessage, fixedIv: fixedIvBase64 };
    } else if (ivBytes.length === 12) {
      return { isValid: true, fixedMessage: encryptedMessage, fixedIv: messageIv };
    } else {
      return { isValid: false, error: `Invalid IV length: ${ivBytes.length} bytes` };
    }
  } catch (error: any) {
    return { isValid: false, error: `Validation error: ${error.message}` };
  }
}

export async function aesGcmDecryptWithMessageKey(ciphertext: string, iv: string, senderEmail: string, recipientEmail: string, messageId: string): Promise<string> {
  // Validate and fix message data format
  const validation = validateMessageData(ciphertext, iv);
  if (!validation.isValid) {
    throw new Error(`Message data validation failed: ${validation.error}`);
  }

  const fixedCiphertext = validation.fixedMessage!;
  const fixedIv = validation.fixedIv!;

  // Derive the same message-specific key
  const key = await deriveMessageKey(senderEmail, recipientEmail, messageId);
  
  // Decrypt with the message-specific key
  const dec = new TextDecoder();
  const ciphertextBuf = Uint8Array.from(atob(fixedCiphertext), c => c.charCodeAt(0));
  const ivBuf = Uint8Array.from(atob(fixedIv), c => c.charCodeAt(0));
  
  const plaintextBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuf },
    key,
    ciphertextBuf
  );
  
  return dec.decode(plaintextBuf);
} 