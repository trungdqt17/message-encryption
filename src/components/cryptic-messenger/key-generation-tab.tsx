// @ts-nocheck
"use client";

import type React from 'react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { OutputField } from './output-field';
import { 
  generateRsaKeyPair, 
  generateAesKey, 
  exportRsaPublicKeyToPem,
  exportRsaPrivateKeyToPem,
  exportAesKeyToRawBase64
} from '@/lib/crypto-utils';
import { useToast } from '@/hooks/use-toast';
import { KeyIcon, ShieldCheckIcon } from 'lucide-react';

interface KeyGenerationTabProps {
  rsaPublicKey: CryptoKey | null;
  setRsaPublicKey: (key: CryptoKey | null) => void;
  rsaPrivateKey: CryptoKey | null;
  setRsaPrivateKey: (key: CryptoKey | null) => void;
  aesKey: CryptoKey | null;
  setAesKey: (key: CryptoKey | null) => void;
}

export function KeyGenerationTab({
  rsaPublicKey,
  setRsaPublicKey,
  rsaPrivateKey,
  setRsaPrivateKey,
  aesKey,
  setAesKey,
}: KeyGenerationTabProps) {
  const [rsaPublicKeyPem, setRsaPublicKeyPem] = useState<string | null>(null);
  const [rsaPrivateKeyPem, setRsaPrivateKeyPem] = useState<string | null>(null);
  const [aesKeyRawBase64, setAesKeyRawBase64] = useState<string | null>(null);

  const [isGeneratingRsa, setIsGeneratingRsa] = useState(false);
  const [isGeneratingAes, setIsGeneratingAes] = useState(false);

  const [rsaSuccess, setRsaSuccess] = useState(false);
  const [aesSuccess, setAesSuccess] = useState(false);

  const { toast } = useToast();

  const handleGenerateRsaKeys = async () => {
    setIsGeneratingRsa(true);
    setRsaSuccess(false);
    try {
      const keyPair = await generateRsaKeyPair();
      setRsaPublicKey(keyPair.publicKey);
      setRsaPrivateKey(keyPair.privateKey);
      setRsaPublicKeyPem(await exportRsaPublicKeyToPem(keyPair.publicKey));
      setRsaPrivateKeyPem(await exportRsaPrivateKeyToPem(keyPair.privateKey));
      setRsaSuccess(true);
      toast({ title: "RSA Keys Generated", description: "Public (PEM) and private (PEM) keys are ready.", variant: "default" });
      setTimeout(() => setRsaSuccess(false), 1500);
    } catch (error) {
      console.error("RSA key generation error:", error);
      toast({ title: "Error", description: "Failed to generate RSA keys.", variant: "destructive" });
    }
    setIsGeneratingRsa(false);
  };

  const handleGenerateAesKey = async () => {
    setIsGeneratingAes(true);
    setAesSuccess(false);
    try {
      const newAesKey = await generateAesKey();
      setAesKey(newAesKey);
      setAesKeyRawBase64(await exportAesKeyToRawBase64(newAesKey));
      setAesSuccess(true);
      toast({ title: "AES Key Generated", description: "AES-GCM key (Raw, Base64) is ready.", variant: "default" });
      setTimeout(() => setAesSuccess(false), 1500);
    } catch (error) {
      console.error("AES key generation error:", error);
      toast({ title: "Error", description: "Failed to generate AES key.", variant: "destructive" });
    }
    setIsGeneratingAes(false);
  };

  return (
    <div className="space-y-6">
      <Card className="bg-card/70 shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <ShieldCheckIcon className="h-6 w-6 text-primary" />
            RSA Key Pair (RSA-OAEP, SHA-256)
          </CardTitle>
          <CardDescription>Generate a public/private key pair for asymmetric encryption. Exported in PEM format.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button onClick={handleGenerateRsaKeys} disabled={isGeneratingRsa} className="w-full sm:w-auto">
            <KeyIcon className="mr-2 h-4 w-4" />
            {isGeneratingRsa ? 'Generating...' : 'Generate RSA Keys'}
          </Button>
          <OutputField label="RSA Public Key (PEM)" value={rsaPublicKeyPem} isLoading={isGeneratingRsa} success={rsaSuccess} rows={10} />
          <OutputField label="RSA Private Key (PEM)" value={rsaPrivateKeyPem} isLoading={isGeneratingRsa} success={rsaSuccess} rows={15} />
        </CardContent>
      </Card>

      <Card className="bg-card/70 shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <KeyIcon className="h-6 w-6 text-primary" />
            AES Key (AES-GCM, 256-bit)
          </CardTitle>
          <CardDescription>Generate a symmetric key for message encryption. Exported as Raw (Base64 encoded).</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button onClick={handleGenerateAesKey} disabled={isGeneratingAes} className="w-full sm:w-auto">
            <KeyIcon className="mr-2 h-4 w-4" />
            {isGeneratingAes ? 'Generating...' : 'Generate AES Key'}
          </Button>
          <OutputField label="AES Key (Raw, Base64)" value={aesKeyRawBase64} isLoading={isGeneratingAes} success={aesSuccess} rows={2} />
        </CardContent>
      </Card>
    </div>
  );
}
