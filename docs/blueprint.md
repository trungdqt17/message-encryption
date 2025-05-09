# **App Name**: Cryptic Messenger

## Core Features:

- Key Generation: Generate RSA key pair and AES GCM key using window.crypto. Display fields to copy the various keys that are generated.
- Message Encryption: Encrypt a user-provided message using the generated AES key (using crypto-js) and display ciphertext
- AES Key Encryption: Encrypt the AES key with the RSA public key (using Node.js crypto and node-forge) to facilitate comparison
- AES Key Decryption: Decrypt the AES key (encrypted with node-forge) using the RSA private key (using Node.js crypto)
- Message Decryption: Decrypt the message using the decrypted AES key, and then display it

## Style Guidelines:

- Primary color: Deep purple (#673AB7) for security and sophistication.
- Secondary color: Light gray (#EEEEEE) for backgrounds and neutral elements.
- Accent: Teal (#009688) for interactive elements and highlights.
- Use a monospace font to differentiate fields which contain generated cryptographic parameters from labels and user input text.
- Use a tabbed or accordion layout to separate the various key generation, encryption and decryption steps.
- Subtle animations when encryption/decryption processes complete to indicate success.