# Secure Handy Safe

Secure Handy Safe is an on-device cryptography web app built with React, TypeScript, and Vite.
All encryption/decryption runs in your browser only.

## Privacy model

- No server upload for cryptographic processing
- Text/file input is processed locally in the browser
- Encryption/decryption keys are handled client-side only

## Supported algorithms

### Symmetric encryption/decryption

- AES-128
- AES-192
- AES-256
- TripleDES (3DES)
- Rabbit
- RC4
- RC4Drop

### Hash algorithms (one-way)

- MD5
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA-3
- RIPEMD160

### AES/3DES options

- Block modes: `CBC`, `ECB`, `CFB`, `OFB`, `CTR`
- Paddings: `Pkcs7`, `ZeroPadding`, `NoPadding`

## Main features

- Text encryption/decryption
- File encryption/decryption (`.enc` flow supported)
- Hash generation
- Multilingual UI (`en`, `ko`, `ja`, `zh`, `es`, `fr`, `de`, `id`, `ar`)

## Crypto format notes

- Uses PBKDF2 (SHA-256) with 100,000 iterations for key derivation
- Encrypted payload format includes metadata (algorithm/mode/padding/salt/iv) for reliable decryption

## Prerequisites

- Node.js 18+
- npm

## Getting started

```sh
npm install
npm run dev
```

## Available scripts

- `npm run dev`: Start development server
- `npm run build`: Build for production
- `npm run preview`: Preview production build
- `npm run lint`: Run ESLint
- `npm run test`: Run tests once
- `npm run test:watch`: Run tests in watch mode
