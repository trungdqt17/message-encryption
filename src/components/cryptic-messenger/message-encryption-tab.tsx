"use client";

import type React from 'react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { OutputField } from './output-field';
import { encryptMessageAesGcm, arrayBufferToBase64 } from '@/lib/crypto-utils';
import { useToast } from '@/hooks/use-toast';
import { LockIcon, MessageSquareIcon } from 'lucide-react';

interface MessageEncryptionTabProps {
  aesKey: CryptoKey | null;
  encryptedMessageBase64: string | null;
  setEncryptedMessageBase64: (data: string | null) => void;
  ivBase64: string | null;
  setIvBase64: (data: string | null) => void;
  setRawEncryptedMessage: (data: ArrayBuffer | null) => void;
  setRawIv: (data: ArrayBuffer | null) => void;
}

export function MessageEncryptionTab({
  aesKey,
  encryptedMessageBase64,
  setEncryptedMessageBase64,
  ivBase64,
  setIvBase64,
  setRawEncryptedMessage,
  setRawIv,
}: MessageEncryptionTabProps) {
  const [messageToEncrypt, setMessageToEncryptState] = useState('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [encryptionSuccess, setEncryptionSuccess] = useState(false);
  const { toast } = useToast();

  const handleEncryptMessage = async () => {
    if (!aesKey) {
      toast({ title: "AES Key Missing", description: "Please generate an AES key first.", variant: "destructive" });
      return;
    }
    if (!messageToEncrypt.trim()) {
      toast({ title: "Empty Message", description: "Please enter a message to encrypt.", variant: "destructive" });
      return;
    }

    setIsEncrypting(true);
    setEncryptionSuccess(false);
    try {
      const { ciphertext, iv } = await encryptMessageAesGcm(messageToEncrypt, aesKey);
      setRawEncryptedMessage(ciphertext);
      setRawIv(iv);
      setEncryptedMessageBase64(arrayBufferToBase64(ciphertext));
      setIvBase64(arrayBufferToBase64(iv));
      setEncryptionSuccess(true);
      toast({ title: "Message Encrypted", description: "Ciphertext and IV are ready.", variant: "default" });
      setTimeout(() => setEncryptionSuccess(false), 1500);
    } catch (error) {
      console.error("Message encryption error:", error);
      toast({ title: "Error", description: "Failed to encrypt message.", variant: "destructive" });
    }
    setIsEncrypting(false);
  };

  return (
    <Card className="bg-card/70 shadow-lg">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-xl">
          <LockIcon className="h-6 w-6 text-primary" />
          Encrypt Message
        </CardTitle>
        <CardDescription>Encrypt your message using the generated AES key.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <label htmlFor="message-input" className="text-sm font-medium text-foreground/80 flex items-center gap-1.5">
             <MessageSquareIcon className="h-4 w-4" /> Message to Encrypt
          </label>
          <Textarea
            id="message-input"
            value={messageToEncrypt}
            onChange={(e) => setMessageToEncryptState(e.target.value)}
            placeholder="Enter your secret message here..."
            rows={4}
            className="bg-background focus:ring-accent"
          />
        </div>
        <Button onClick={handleEncryptMessage} disabled={isEncrypting || !aesKey} className="w-full sm:w-auto">
          <LockIcon className="mr-2 h-4 w-4" />
          {isEncrypting ? 'Encrypting...' : 'Encrypt Message'}
        </Button>
        <OutputField label="Ciphertext (Base64)" value={encryptedMessageBase64} isLoading={isEncrypting} success={encryptionSuccess} rows={4} />
        <OutputField label="Initialization Vector (IV) (Base64)" value={ivBase64} isLoading={isEncrypting} success={encryptionSuccess} rows={2} />
      </CardContent>
    </Card>
  );
}