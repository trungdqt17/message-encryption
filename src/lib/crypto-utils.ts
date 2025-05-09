// src/lib/crypto-utils.ts
import CryptoJS from 'crypto-js';
// Type-only import for WordArray and CipherParams from 'crypto-js'
// These types represent instances (e.g., of CryptoJS.lib.WordArray).
import type { WordArray as WordArrayType, CipherParams as CipherParamsType } from 'crypto-js';


// Helper function to convert ArrayBuffer to CryptoJS.lib.WordArray
function arrayBufferToWordArray(buffer: ArrayBuffer): WordArrayType {
  const typedArray = new Uint8Array(buffer);
  // CryptoJS.lib.WordArray is a class/object with a create method
  return CryptoJS.lib.WordArray.create(typedArray as any); 
}

// Helper function to convert CryptoJS.lib.WordArray to ArrayBuffer
function wordArrayToArrayBuffer(wordArray: WordArrayType): ArrayBuffer {
  const { words, sigBytes } = wordArray;
  const u8 = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return u8.buffer;
}


export async function generateRsaKeyPair(): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  return window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-1', // Using SHA-1 as requested
    },
    true, // exportable
    ['encrypt', 'decrypt']
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

function toPem(dataBuffer: ArrayBuffer, type: 'PUBLIC' | 'PRIVATE'): string {
  const base64String = arrayBufferToBase64(dataBuffer);
  const header = `-----BEGIN ${type} KEY-----`;
  const footer = `-----END ${type} KEY-----`;
  
  let pemString = `${header}\n`;
  for (let i = 0; i < base64String.length; i += 64) {
    pemString += base64String.substring(i, Math.min(i + 64, base64String.length)) + '\n';
  }
  pemString += footer;
  return pemString;
}

export async function exportRsaPublicKeyToPem(key: CryptoKey): Promise<string> {
  const spkiBuffer = await window.crypto.subtle.exportKey('spki', key);
  return toPem(spkiBuffer, 'PUBLIC');
}

export async function exportRsaPrivateKeyToPem(key: CryptoKey): Promise<string> {
  const pkcs8Buffer = await window.crypto.subtle.exportKey('pkcs8', key);
  return toPem(pkcs8Buffer, 'PRIVATE');
}

export async function exportAesKeyToRawBase64(key: CryptoKey): Promise<string> {
  const rawBuffer = await window.crypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(rawBuffer);
}

export async function encryptMessageAesGcm(
  message: string,
  aesKey: CryptoKey // This is a Web Crypto API CryptoKey
): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }> {
  // Export the Web Crypto AES key to raw format to be used by CryptoJS
  const rawAesKeyBuffer = await window.crypto.subtle.exportKey('raw', aesKey);
  const keyWordArray = arrayBufferToWordArray(rawAesKeyBuffer); // Convert raw key to CryptoJS WordArray

  // Generate IV (Initialization Vector) - CryptoJS GCM typically uses 12 bytes
  const ivArrayBuffer = window.crypto.getRandomValues(new Uint8Array(12));
  const ivWordArray = arrayBufferToWordArray(ivArrayBuffer); // Convert IV to CryptoJS WordArray
  
  const messageUtf8 = CryptoJS.enc.Utf8.parse(message); // Parse message to CryptoJS WordArray (UTF-8)

  // Encrypt using CryptoJS.AES.encrypt
  // The result is a CipherParams object which includes the ciphertext
  const encrypted: CipherParamsType = CryptoJS.AES.encrypt(messageUtf8, keyWordArray, {
    iv: ivWordArray,
    mode: CryptoJS.mode.GCM,
    padding: CryptoJS.pad.NoPadding, // GCM does not use padding
  });
  
  // encrypted.ciphertext is a WordArray. Convert it to ArrayBuffer.
  const ciphertextArrayBuffer = wordArrayToArrayBuffer(encrypted.ciphertext);

  return { ciphertext: ciphertextArrayBuffer, iv: ivArrayBuffer }; // Return ArrayBuffer for ciphertext and IV
}

export async function decryptMessageAesGcm(
  ciphertext: ArrayBuffer, // Ciphertext as ArrayBuffer
  iv: ArrayBuffer,         // IV as ArrayBuffer
  aesKey: CryptoKey       // Web Crypto API CryptoKey
): Promise<string> {
  // Export the Web Crypto AES key to raw format
  const rawAesKeyBuffer = await window.crypto.subtle.exportKey('raw', aesKey);
  const keyWordArray = arrayBufferToWordArray(rawAesKeyBuffer); // Convert to CryptoJS WordArray

  const ivWordArray = arrayBufferToWordArray(iv);                 // Convert IV to CryptoJS WordArray
  const ciphertextWordArray = arrayBufferToWordArray(ciphertext); // Convert ciphertext to CryptoJS WordArray

  // Create a CipherParams object for decryption input.
  // This is what CryptoJS.AES.decrypt expects if the first argument isn't a base64/hex string.
  const cipherParamsInput = CryptoJS.lib.CipherParams.create({
    ciphertext: ciphertextWordArray
  });

  // Decrypt using CryptoJS.AES.decrypt
  const decrypted: WordArrayType = CryptoJS.AES.decrypt(cipherParamsInput, keyWordArray, {
    iv: ivWordArray,
    mode: CryptoJS.mode.GCM,
    padding: CryptoJS.pad.NoPadding,
  });
  
  // Convert the decrypted WordArray back to a UTF-8 string
  return decrypted.toString(CryptoJS.enc.Utf8);
}

export async function encryptAesKeyMaterialWithRsa(
  aesKey: CryptoKey,
  rsaPublicKey: CryptoKey
): Promise<ArrayBuffer> {
  const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
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
  const decryptedRawAesKey = await window.crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
    },
    rsaPrivateKey,
    encryptedAesKeyMaterial
  );
  return window.crypto.subtle.importKey(
    'raw',
    decryptedRawAesKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, 
    ['encrypt', 'decrypt']
  );
}
