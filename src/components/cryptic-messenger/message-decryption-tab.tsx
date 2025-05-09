"use client";

import type React from 'react';
import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { OutputField } from './output-field';
import { decryptAES } from '@/lib/crypto-utils';
import { useToast } from '@/hooks/use-toast';
import { Textarea } from '@/components/ui/textarea';
import { UnlockIcon, MessageCircleIcon, HashIcon, KeyIcon } from 'lucide-react';

interface MessageDecryptionTabProps {
  // Use either the originally generated AES key or the one decrypted via RSA
  aesKeyToUseForDecryption: string; 
  rawEncryptedMessage: string; // From encryption step
  rawIv: string; // From encryption step
  decryptedMessage: string;
  setDecryptedMessage: (message: string) => void;
}

export function MessageDecryptionTab({
  aesKeyToUseForDecryption,
  rawEncryptedMessage,
  rawIv,
  decryptedMessage,
  setDecryptedMessage,
}: MessageDecryptionTabProps) {
  const [ciphertextInput, setCiphertextInput] = useState('');
  const [ivInput, setIvInput] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptionSuccess, setDecryptionSuccess] = useState(false);

  const { toast } = useToast();

  // Effect to prefill inputs if raw data exists (e.g., from previous encryption step)
  useEffect(() => {
    if (rawEncryptedMessage) {
      setCiphertextInput(rawEncryptedMessage);
    }
    if (rawIv) {
      setIvInput(rawIv);
    }
  }, [rawEncryptedMessage, rawIv]);

  const handleDecryptMessage = async () => {
    if (!aesKeyToUseForDecryption) {
      toast({ title: "AES Key Missing", description: "An AES key is required for decryption.", variant: "destructive" });
      return;
    }
    if (!ciphertextInput.trim() || !ivInput.trim()) {
      toast({ title: "Data Missing", description: "Ciphertext and IV are required.", variant: "destructive" });
      return;
    }

    setIsDecrypting(true);
    setDecryptionSuccess(false);
    try {
      const decrypted = decryptAES(ciphertextInput, aesKeyToUseForDecryption, ivInput);
      setDecryptedMessage(decrypted);
      setDecryptionSuccess(true);
      toast({ title: "Message Decrypted", description: "The original message has been recovered.", variant: "default" });
      setTimeout(() => setDecryptionSuccess(false), 1500);
    } catch (error) {
      console.error("Message decryption error:", error);
      toast({ title: "Error", description: "Failed to decrypt message. Check keys, ciphertext, and IV.", variant: "destructive" });
      setDecryptedMessage(''); // Clear previous decrypted message on error
    }
    setIsDecrypting(false);
  };

  return (
    <Card className="bg-card/70 shadow-lg">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-xl">
          <UnlockIcon className="h-6 w-6 text-primary" />
          Decrypt Message
        </CardTitle>
        <CardDescription>Decrypt the ciphertext using the AES key and IV.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <label htmlFor="ciphertext-input" className="text-sm font-medium text-foreground/80 flex items-center gap-1.5">
            <MessageCircleIcon className="h-4 w-4" /> Ciphertext (Base64)
          </label>
          <Textarea
            id="ciphertext-input"
            value={ciphertextInput}
            onChange={(e) => setCiphertextInput(e.target.value)}
            placeholder="Paste Base64 encoded ciphertext here..."
            rows={4}
            className="font-mono bg-background focus:ring-accent"
            aria-label="Ciphertext input"
          />
        </div>
        <div className="space-y-1">
          <label htmlFor="iv-input" className="text-sm font-medium text-foreground/80 flex items-center gap-1.5">
            <HashIcon className="h-4 w-4" /> IV (Base64)
          </label>
          <Textarea
            id="iv-input"
            value={ivInput}
            onChange={(e) => setIvInput(e.target.value)}
            placeholder="Paste Base64 encoded IV here..."
            rows={2}
            className="font-mono bg-background focus:ring-accent"
            aria-label="IV input"
          />
        </div>
         <p className="text-xs text-muted-foreground flex items-center gap-1.5">
          <KeyIcon className="h-3 w-3" /> Using AES key: {aesKeyToUseForDecryption ? 'Available' : 'Not Available (Generate or Decrypt first)'}
        </p>
        <Button
          onClick={handleDecryptMessage}
          disabled={isDecrypting || !aesKeyToUseForDecryption || !ciphertextInput || !ivInput}
          className="w-full sm:w-auto"
        >
          <UnlockIcon className="mr-2 h-4 w-4" />
          {isDecrypting ? 'Decrypting...' : 'Decrypt Message'}
        </Button>
        <OutputField
          label="Decrypted Message"
          value={decryptedMessage}
          isLoading={isDecrypting}
          isMonospace={false} // Original message might not be monospace
          success={decryptionSuccess}
          rows={4}
          placeholder="Decrypted message will appear here."
        />
      </CardContent>
    </Card>
  );
}