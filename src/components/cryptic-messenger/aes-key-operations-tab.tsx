// @ts-nocheck
"use client";

import type React from 'react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription }  from '@/components/ui/card';
import { OutputField } from './output-field';
import {
  encryptAesKeyMaterialWithRsa,
  decryptAesKeyMaterialWithRsa,
  exportAesKeyToRawBase64, // Changed from exportCryptoKeyToJwk
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from '@/lib/crypto-utils';
import { useToast } from '@/hooks/use-toast';
import { KeyRoundIcon, LockKeyholeIcon, UnlockKeyholeIcon } from 'lucide-react';

interface AesKeyOperationsTabProps {
  aesKey: CryptoKey | null;
  rsaPublicKey: CryptoKey | null;
  rsaPrivateKey: CryptoKey | null;
  encryptedAesKeyMaterialBase64: string | null;
  setEncryptedAesKeyMaterialBase64: (data: string | null) => void;
  setRawEncryptedAesKeyMaterial: (data: ArrayBuffer | null) => void;
  decryptedAesKeyForVerification: CryptoKey | null;
  setDecryptedAesKeyForVerification: (key: CryptoKey | null) => void;
}

export function AesKeyOperationsTab({
  aesKey,
  rsaPublicKey,
  rsaPrivateKey,
  encryptedAesKeyMaterialBase64,
  setEncryptedAesKeyMaterialBase64,
  setRawEncryptedAesKeyMaterial,
  decryptedAesKeyForVerification,
  setDecryptedAesKeyForVerification,
}: AesKeyOperationsTabProps) {
  const [isEncryptingAes, setIsEncryptingAes] = useState(false);
  const [isDecryptingAes, setIsDecryptingAes] = useState(false);
  const [decryptedAesKeyRawBase64, setDecryptedAesKeyRawBase64] = useState<string | null>(null); // Changed from decryptedAesKeyJwk

  const [encryptSuccess, setEncryptSuccess] = useState(false);
  const [decryptSuccess, setDecryptSuccess] = useState(false);

  const { toast } = useToast();

  const handleEncryptAesKey = async () => {
    if (!aesKey || !rsaPublicKey) {
      toast({ title: "Keys Missing", description: "AES key and RSA public key are required.", variant: "destructive" });
      return;
    }
    setIsEncryptingAes(true);
    setEncryptSuccess(false);
    try {
      const encryptedMaterial = await encryptAesKeyMaterialWithRsa(aesKey, rsaPublicKey);
      setRawEncryptedAesKeyMaterial(encryptedMaterial);
      setEncryptedAesKeyMaterialBase64(arrayBufferToBase64(encryptedMaterial));
      setEncryptSuccess(true);
      toast({ title: "AES Key Encrypted", description: "AES key material encrypted with RSA public key.", variant: "default" });
      setTimeout(() => setEncryptSuccess(false), 1500);
    } catch (error) {
      console.error("AES key encryption error:", error);
      toast({ title: "Error", description: "Failed to encrypt AES key.", variant: "destructive" });
    }
    setIsEncryptingAes(false);
  };

  const handleDecryptAesKey = async () => {
    if (!encryptedAesKeyMaterialBase64 || !rsaPrivateKey) {
      toast({ title: "Data Missing", description: "Encrypted AES key and RSA private key are required.", variant: "destructive" });
      return;
    }
    setIsDecryptingAes(true);
    setDecryptSuccess(false);
    try {
      const rawEncryptedMaterial = base64ToArrayBuffer(encryptedAesKeyMaterialBase64);
      const decryptedKey = await decryptAesKeyMaterialWithRsa(rawEncryptedMaterial, rsaPrivateKey);
      setDecryptedAesKeyForVerification(decryptedKey);
      setDecryptedAesKeyRawBase64(await exportAesKeyToRawBase64(decryptedKey)); // Changed from exportCryptoKeyToJwk
      setDecryptSuccess(true);
      toast({ title: "AES Key Decrypted", description: "AES key material decrypted with RSA private key.", variant: "default" });
      setTimeout(() => setDecryptSuccess(false), 1500);
    } catch (error) {
      console.error("AES key decryption error:", error);
      toast({ title: "Error", description: "Failed to decrypt AES key. Ensure correct keys and data.", variant: "destructive" });
    }
    setIsDecryptingAes(false);
  };

  return (
    <div className="space-y-6">
      <Card className="bg-card/70 shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <LockKeyholeIcon className="h-6 w-6 text-primary" />
            Encrypt AES Key with RSA
          </CardTitle>
          <CardDescription>Encrypt the generated AES key using the RSA public key (simulating key wrapping).</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button
            onClick={handleEncryptAesKey}
            disabled={isEncryptingAes || !aesKey || !rsaPublicKey}
            className="w-full sm:w-auto"
          >
             <KeyRoundIcon className="mr-2 h-4 w-4" />
            {isEncryptingAes ? 'Encrypting...' : 'Encrypt AES Key'}
          </Button>
          <OutputField
            label="Encrypted AES Key Material (Base64)"
            value={encryptedAesKeyMaterialBase64}
            isLoading={isEncryptingAes}
            success={encryptSuccess}
            rows={4}
          />
        </CardContent>
      </Card>

      <Card className="bg-card/70 shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
             <UnlockKeyholeIcon className="h-6 w-6 text-primary" />
            Decrypt AES Key with RSA
          </CardTitle>
          <CardDescription>Decrypt the encrypted AES key material using the RSA private key.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button
            onClick={handleDecryptAesKey}
            disabled={isDecryptingAes || !encryptedAesKeyMaterialBase64 || !rsaPrivateKey}
            className="w-full sm:w-auto"
          >
            <KeyRoundIcon className="mr-2 h-4 w-4" />
            {isDecryptingAes ? 'Decrypting...' : 'Decrypt AES Key'}
          </Button>
          <OutputField
            label="Decrypted AES Key (Raw, Base64 for verification)" // Changed label
            value={decryptedAesKeyRawBase64} // Changed from decryptedAesKeyJwk
            isLoading={isDecryptingAes}
            success={decryptSuccess}
            rows={2} // Changed from 4, as raw base64 is shorter
            placeholder="Decrypted AES key (Raw, Base64) will appear here."
          />
        </CardContent>
      </Card>
    </div>
  );
}
