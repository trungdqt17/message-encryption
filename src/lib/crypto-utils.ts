/// <reference lib="webworker" />

// Encryption Dedicated Worker
import CryptoJS from "crypto-js"

function generateAesCbcIv() {
  const buf = new Uint8Array(16)
  window.crypto.getRandomValues(buf)
  return Array.from(buf)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}
function arrayBufferToBase64(buffer: ArrayBuffer) {
  const byteArray = new Uint8Array(buffer)
  const binary = Array.from(byteArray, byte => String.fromCharCode(byte)).join(
    "",
  )
  return btoa(binary)
}
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}
async function exportPrivateKeyAsPem(privateKey: CryptoKey) {
  try {
    const pkcs8Data = await self.crypto.subtle.exportKey("pkcs8", privateKey)

    // Step 2: Convert ArrayBuffer to base64 string
    const base64Key = arrayBufferToBase64(pkcs8Data)

    // Step 3: Format as PEM by adding header and footer
    const pemKey =
      "-----BEGIN PRIVATE KEY-----" +
      // Insert line breaks every 64 characters for proper PEM formatting
      (base64Key.match(/.{1,64}/g) ?? []).join("") +
      "-----END PRIVATE KEY-----"

    return pemKey
  } catch (error) {
    throw new Error(
      `Error exporting private key as PEM: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
}
async function exportPublicKeyAsPem(publicKey: CryptoKey) {
  try {
    // Step 1: Export the key to SPKI format (returns ArrayBuffer)
    const spkiData = await self.crypto.subtle.exportKey("spki", publicKey)

    // Step 2: Convert ArrayBuffer to base64 string
    const base64Key = arrayBufferToBase64(spkiData)

    // Step 3: Format as PEM by adding header and footer
    const pemKey =
      "-----BEGIN PUBLIC KEY-----" +
      // Insert line breaks every 64 characters for proper PEM formatting
      (base64Key.match(/.{1,64}/g) ?? []).join("") +
      "-----END PUBLIC KEY-----"

    return pemKey
  } catch (error) {
    throw new Error(
      `Error exporting public key as PEM: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
}
async function exportDerivedKeyAsJWK(derivedKey: CryptoKey) {
  try {
    const jwk = await self.crypto.subtle.exportKey("jwk", derivedKey)
    return jwk
  } catch (error) {
    throw new Error(
      `Error exporting derived key as PEM: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
}
export function encryptAES(
  message: string,
  encKey: string,
) {
  const iv = generateAesCbcIv()

  let ciphertext = ""
  try {
    ciphertext = CryptoJS.AES.encrypt(
      message,
      CryptoJS.enc.Base64.parse(encKey),
      {
        iv: CryptoJS.enc.Hex.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      },
    ).toString()
  } catch (err) {
    throw new Error(
      `Failed to encrypt message: ${err instanceof Error ? err.message : "Unknown error"}`,
    )
  }
  return { ciphertext, iv }
}
export function decryptAES(
  ciphertext: string,
  encKey: string,
  ivKey: string,
): string {
  let decrypted = ""

  try {
    decrypted = CryptoJS.AES.decrypt(
      ciphertext,
      CryptoJS.enc.Base64.parse(encKey),
      {
        iv: CryptoJS.enc.Hex.parse(ivKey),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      },
    ).toString(CryptoJS.enc.Utf8)
  } catch (err) {
    throw new Error(
      `Failed to decrypt message: ${err instanceof Error ? err.message : "Unknown error"}`,
    )
  }

  return decrypted
}
// Generate RSA-OAEP key pair and export as PEM
export async function generateRsaKeyPairPem() {
  try {
    const keyPair = await self.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    )
    const publicKeyPem = await exportPublicKeyAsPem(keyPair.publicKey)
    const privateKeyPem = await exportPrivateKeyAsPem(keyPair.privateKey)

    return {
      publicKey: publicKeyPem,
      privateKey: privateKeyPem,
    }
  } catch (err) {
    throw new Error(
      `Failed to generate Aes Gcm Key: ${err instanceof Error ? err.message : "Unknown error"}`,
    )
  }

}
//generate AES-GCM key
export async function generateAesGcmKeyAsRaw() {
  try {
    const key = await self.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    )
    const exportedKey = await self.crypto.subtle.exportKey("raw", key)

    return arrayBufferToBase64(exportedKey)
  } catch (err) {
    throw new Error(
      `Failed to generate Aes Gcm Key: ${err instanceof Error ? err.message : "Unknown error"}`,
    )
  }
}
async function deriveKeyFromPassword(
  password: string,
  salt: string,
  iterations = 100000,
) {
  const encoder = new TextEncoder()
  const passwordData = encoder.encode(password)
  const saltData = encoder.encode(salt || "e2ee_salt")

  // Tạo material key từ mật khẩu
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    passwordData,
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"],
  )

  // Tạo khóa AES-GCM từ PBKDF2
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltData,
      iterations: iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
}
export async function encryptAesKeyMaterialWithRsa(publicKeyPem: string, aesKeyRaw: string) {
  const pemHeader = '-----BEGIN PUBLIC KEY-----';
  const pemFooter = '-----END PUBLIC KEY-----';
  if (!publicKeyPem || !aesKeyRaw) {
    throw new Error('Private key and encrypted data must be provided');
  }

  if (!publicKeyPem.includes(pemHeader)) {
    throw new Error('Invalid PEM format for public key');
  }

  const pemBody = publicKeyPem
    .replace(pemHeader, '')
    .replace(pemFooter, '')
    .replace(/\s/g, '');

  try {
    const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

    // 🟡 Không khai báo 'hash', trình duyệt sẽ dùng mặc định: SHA-1
    const cryptoKey = await window.crypto.subtle.importKey(
      'spki',
      binaryDer.buffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-1'
      },
      false,
      ['encrypt']
    );

    const encodedText = new TextEncoder().encode(aesKeyRaw);

    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      cryptoKey,
      encodedText
    );

    return arrayBufferToBase64(encrypted);
  } catch (err) {
    throw new Error(
      `Failed to decrypt Aes Key: ${err instanceof Error ? err.message : "Unknown error"}`,
    )
  }

}
export async function decryptAesKeyMaterialWithRsa(privateKeyPem: string, encryptedAesRaw: string) {
  if (!privateKeyPem || !encryptedAesRaw) {
    throw new Error('Private key and encrypted data must be provided');
  }

  if (!privateKeyPem.includes('-----BEGIN PRIVATE KEY-----') &&
    !privateKeyPem.includes('-----BEGIN RSA PRIVATE KEY-----')) {
    throw new Error('Invalid PEM format for private key');
  }

  try {
    // Convert PEM to binary
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';

    const pemBody = privateKeyPem
      .replace(pemHeader, '')
      .replace(pemFooter, '')
      .replace(/\s/g, '');

    // Decode base64 to binary
    const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

    const cryptoKey = await window.crypto.subtle.importKey(
      'pkcs8',
      binaryDer.buffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-1',
      },
      false,
      ['decrypt']
    );
    // Convert base64 to ArrayBuffer
    let encryptedBuffer = base64ToArrayBuffer(encryptedAesRaw);

    // Decrypt
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      cryptoKey,
      encryptedBuffer
    );

    // Convert ArrayBuffer to string
    return new TextDecoder().decode(decrypted);
  } catch (err) {
    throw new Error(
      `Failed to decrypt Aes Key: ${err instanceof Error ? err.message : "Unknown error"}`,
    )
  }
}