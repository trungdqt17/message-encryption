"use client";

import type React from 'react';
import { useState, useEffect } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyGenerationTab } from '@/components/cryptic-messenger/key-generation-tab';
import { MessageEncryptionTab } from '@/components/cryptic-messenger/message-encryption-tab';
import { AesKeyOperationsTab } from '@/components/cryptic-messenger/aes-key-operations-tab';
import { MessageDecryptionTab } from '@/components/cryptic-messenger/message-decryption-tab';
import { Toaster } from "@/components/ui/toaster";
import { ShieldAlertIcon } from 'lucide-react';

export default function CrypticMessengerPage() {
  // RSA Keys
  const [rsaPublicKey, setRsaPublicKey] = useState<string>('');
  const [rsaPrivateKey, setRsaPrivateKey] = useState<string>('');

  // AES Key
  const [aesKey, setAesKey] = useState<string>("");

  // Message Encryption
  const [rawEncryptedMessage, setRawEncryptedMessage] = useState<string>('');
  const [encryptedMessageBase64, setEncryptedMessageBase64] = useState<string>("");
  const [rawIv, setRawIv] = useState<string>("");
  const [ivBase64, setIvBase64] = useState<string>("");

  // AES Key Encryption/Decryption
  const [rawEncryptedAesKeyMaterial, setRawEncryptedAesKeyMaterial] = useState<string>("");
  const [encryptedAesKeyMaterialBase64, setEncryptedAesKeyMaterialBase64] = useState<string>("");
  
  // Message Decryption
  const [decryptedMessage, setDecryptedMessage] = useState<string>("");
  const [decryptedAesKeyForVerification, setDecryptedAesKeyForVerification] = useState("");

  const [isClient, setIsClient] = useState(false);
  useEffect(() => {
    setIsClient(true);
  }, []);

  if (!isClient) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen p-4 bg-[hsl(var(--app-background))]">
        <p className="text-lg text-[hsl(var(--app-foreground))]">Loading Cryptic Messenger...</p>
      </div>
    );
  }
  
  // Determine which AES key to use for final decryption
  // Priority: 1. AES key decrypted via RSA, 2. Original AES key
  const aesKeyToUseForDecryption = aesKey;

  return (
    <div className="container mx-auto p-4 md:p-8 min-h-screen flex flex-col items-center bg-[hsl(var(--app-background))]">
      <header className="mb-8 text-center">
        <h1 className="text-4xl font-bold text-primary tracking-tight">Cryptic Messenger</h1>
        <p className="text-lg text-muted-foreground mt-2">Secure your messages with client-side cryptography.</p>
      </header>
      
      <div className="w-full max-w-3xl">
        <Tabs defaultValue="key-generation" className="w-full">
          <TabsList className="grid w-full grid-cols-2 sm:grid-cols-4 mb-6 bg-muted/50 p-1.5 rounded-lg">
            <TabsTrigger value="key-generation" className="text-xs sm:text-sm py-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">1. Keys</TabsTrigger>
            <TabsTrigger value="message-encryption" className="text-xs sm:text-sm py-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">2. Encrypt Msg</TabsTrigger>
            <TabsTrigger value="aes-key-ops" className="text-xs sm:text-sm py-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">3. AES Key Ops</TabsTrigger>
            <TabsTrigger value="message-decryption" className="text-xs sm:text-sm py-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">4. Decrypt Msg</TabsTrigger>
          </TabsList>

          <TabsContent value="key-generation" className="rounded-lg shadow-xl bg-card p-6">
            <KeyGenerationTab
              rsaPublicKey={rsaPublicKey} setRsaPublicKey={setRsaPublicKey}
              rsaPrivateKey={rsaPrivateKey} setRsaPrivateKey={setRsaPrivateKey}
              aesKey={aesKey} setAesKey={setAesKey}
            />
          </TabsContent>
          <TabsContent value="message-encryption" className="rounded-lg shadow-xl bg-card p-6">
            <MessageEncryptionTab
              aesKey={aesKey}
              setRawIv={setRawIv}
              ivBase64={ivBase64} 
              setIvBase64={setIvBase64}
              setRawEncryptedMessage={setRawEncryptedMessage}
              encryptedMessageBase64={encryptedMessageBase64} 
              setEncryptedMessageBase64={setEncryptedMessageBase64}
            />
          </TabsContent>
          <TabsContent value="aes-key-ops" className="rounded-lg shadow-xl bg-card p-6">
            <AesKeyOperationsTab
              aesKey={aesKey}
              rsaPublicKey={rsaPublicKey}
              rsaPrivateKey={rsaPrivateKey}
              encryptedAesKeyMaterialBase64={encryptedAesKeyMaterialBase64} 
              setEncryptedAesKeyMaterialBase64={setEncryptedAesKeyMaterialBase64}
              setRawEncryptedAesKeyMaterial={setRawEncryptedAesKeyMaterial}
              decryptedAesKeyForVerification={decryptedAesKeyForVerification}
              setDecryptedAesKeyForVerification={setDecryptedAesKeyForVerification}
            />
          </TabsContent>
          <TabsContent value="message-decryption" className="rounded-lg shadow-xl bg-card p-6">
            <MessageDecryptionTab
              aesKeyToUseForDecryption={aesKeyToUseForDecryption}
              rawEncryptedMessage={rawEncryptedMessage}
              rawIv={rawIv}
              decryptedMessage={decryptedMessage}
              setDecryptedMessage={setDecryptedMessage}
            />
          </TabsContent>
        </Tabs>
      </div>
      <Toaster />
      <footer className="mt-12 text-center text-sm text-muted-foreground">
        <p className="flex items-center justify-center gap-2">
           <ShieldAlertIcon className="h-4 w-4 text-amber-500" />
          Educational tool. Do not use for real-world sensitive data encryption without expert review.
        </p>
        <p>&copy; {new Date().getFullYear()} Cryptic Messenger. All operations are client-side.</p>
      </footer>
    </div>
  );
}