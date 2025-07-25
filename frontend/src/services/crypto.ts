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

export async function signMessage(privateKey: CryptoKey, message: ArrayBuffer) {
  // TODO: Use Web Crypto API to sign message
}

export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const spki = await window.crypto.subtle.exportKey('spki', publicKey);
  const b64 = window.btoa(String.fromCharCode(...new Uint8Array(spki)));
  const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;
  return pem;
} 