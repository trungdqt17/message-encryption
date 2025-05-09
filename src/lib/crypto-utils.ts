// src/lib/crypto-utils.ts

export async function generateRsaKeyPair(): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  return window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true, // exportable
    ['encrypt', 'decrypt'] // private key can decrypt, public key can encrypt
  );
}

export async function generateAesKey(): Promise<CryptoKey> {
  return window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // exportable
    ['encrypt', 'decrypt']
  );
}

export async function exportCryptoKeyToJwk(key: CryptoKey): Promise<string> {
  const jwk = await window.crypto.subtle.exportKey('jwk', key);
  return JSON.stringify(jwk, null, 2);
}

export function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToArrayBuffer(hex: string): ArrayBuffer {
  const typedArray = new Uint8Array(hex.match(/[\da-f]{2}/gi)!.map(h => parseInt(h, 16)));
  return typedArray.buffer;
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

export async function encryptMessageAesGcm(
  message: string,
  key: CryptoKey
): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Recommended IV size for AES-GCM is 12 bytes
  const encodedMessage = new TextEncoder().encode(message);
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    encodedMessage
  );
  return { ciphertext, iv };
}

export async function decryptMessageAesGcm(
  ciphertext: ArrayBuffer,
  iv: ArrayBuffer,
  key: CryptoKey
): Promise<string> {
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decrypted);
}

export async function encryptAesKeyMaterialWithRsa(
  aesKey: CryptoKey,
  rsaPublicKey: CryptoKey
): Promise<ArrayBuffer> {
  // Export the AES key as raw bytes
  const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
  // Encrypt the raw AES key bytes with RSA-OAEP
  return window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    rsaPublicKey,
    rawAesKey
  );
}

export async function decryptAesKeyMaterialWithRsa(
  encryptedAesKeyMaterial: ArrayBuffer,
  rsaPrivateKey: CryptoKey
): Promise<CryptoKey> {
  // Decrypt the raw AES key bytes
  const decryptedRawAesKey = await window.crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
    },
    rsaPrivateKey,
    encryptedAesKeyMaterial
  );
  // Import the decrypted raw bytes back into an AES-GCM CryptoKey
  return window.crypto.subtle.importKey(
    'raw',
    decryptedRawAesKey,
    {
      name: 'AES-GCM',
      length: 256, // Ensure this matches the original key length
    },
    true, // exportable
    ['encrypt', 'decrypt']
  );
}