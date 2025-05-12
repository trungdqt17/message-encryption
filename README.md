# Cryptic Messenger

Cryptic Messenger is a Next.js application demonstrating client-side cryptographic operations. It allows users to generate RSA and AES keys, encrypt messages using AES, wrap AES keys with RSA, and decrypt messages. All cryptographic operations are performed in the browser, ensuring that sensitive data like private keys and plaintext messages are never sent to a server.

## Core Technologies

- **Next.js (App Router)**: For the React framework and application structure.
- **TypeScript**: For type safety and improved developer experience.
- **Tailwind CSS**: For utility-first styling.
- **ShadCN UI**: For pre-built, accessible UI components.
- **crypto-js**: For AES encryption and decryption.
- **Web Crypto API (subtle.crypto)**: For RSA key generation, AES key generation, and RSA encryption/decryption (key wrapping).

## Key Features

1.  **RSA Key Pair Generation**:
    *   Generates a 2048-bit RSA-OAEP key pair (public and private keys).
    *   Uses SHA-256 as the hash algorithm for RSA-OAEP.
    *   Exports keys in PEM format.

2.  **AES Key Generation**:
    *   Generates a 256-bit AES-CBC key.
    *   Exports the key in raw format (Base64 encoded).

3.  **Message Encryption**:
    *   Encrypts user-provided messages using the generated AES-CBC key.
    *   Generates a random Initialization Vector (IV) for each encryption.
    *   Outputs ciphertext and IV, both Base64 encoded.

4.  **AES Key Operations (Wrapping/Unwrapping)**:
    *   **Encrypt AES Key**: Encrypts (wraps) the generated AES key material using the RSA public key.
    *   **Decrypt AES Key**: Decrypts (unwraps) the encrypted AES key material using the RSA private key. This demonstrates secure key exchange simulation.

5.  **Message Decryption**:
    *   Decrypts ciphertext using the appropriate AES key (either the originally generated one or the one unwrapped via RSA) and the corresponding IV.
    *   Recovers the original plaintext message.

## Client-Side Operations

All cryptographic operations, including key generation, encryption, and decryption, are performed entirely within the user's browser. No private keys or unencrypted sensitive data are transmitted over the network.

## Getting Started

### Prerequisites

- Node.js (version 18.x or later recommended)
- npm or yarn

### Installation

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    cd cryptic-messenger
    ```

2.  Install dependencies:
    ```bash
    npm install
    # or
    yarn install
    ```

### Running the Development Server

To start the development server:

```bash
npm run dev
# or
yarn dev
```

The application will typically be available at `http://localhost:9002`.

### Building for Production

To build the application for production:

```bash
npm run build
# or
yarn build
```

### Starting the Production Server

After building, you can start the production server:

```bash
npm run start
# or
yarn start
```

## Project Structure

-   `src/app/`: Contains the main application pages and layout.
    -   `page.tsx`: The main page for the Cryptic Messenger application.
    -   `layout.tsx`: The root layout for the application.
    -   `globals.css`: Global styles and Tailwind CSS configuration.
-   `src/components/`: Contains UI components.
    -   `ui/`: ShadCN UI components.
    -   `cryptic-messenger/`: Components specific to the Cryptic Messenger functionality (e.g., tabs for key generation, encryption, decryption).
-   `src/lib/`: Contains utility functions.
    -   `crypto-utils.ts`: Core cryptographic functions using Web Crypto API and `crypto-js`.
    -   `utils.ts`: General utility functions (e.g., `cn` for Tailwind class merging).
-   `src/hooks/`: Custom React hooks.
    -   `use-toast.ts`: Hook for managing toast notifications.
-   `public/`: Static assets.
-   `next.config.ts`: Next.js configuration.
-   `tailwind.config.ts`: Tailwind CSS configuration.
-   `tsconfig.json`: TypeScript configuration.

## Security Note

This application is an educational tool designed to demonstrate client-side cryptographic principles. While it uses standard cryptographic libraries, **it should not be used for real-world sensitive data encryption without a thorough security review by cryptography experts.** For production-grade security, consider established, audited libraries and protocols, and be mindful of secure key management practices.
```