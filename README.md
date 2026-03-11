# Secure Handy Safe

Secure Handy Safe is an on-device cryptography web app built with React, TypeScript, and Vite.
All encryption/decryption runs in your browser only.

## Links

- Live: https://crypt.localtool.tech/
- LeanVibe: https://leanvibe.io/vibe/secure-handy-safe-mmk5u1kz

## Privacy model

- No server upload for cryptographic processing
- Text/file input is processed locally in the browser
- Encryption/decryption keys are handled client-side only

## Supported algorithms

### Symmetric encryption/decryption (PGP compatible)

- OpenPGP.js symmetric message format
- Configurable symmetric algorithm:
  - `aes128`, `aes192`, `aes256`, `tripledes`, `cast5`, `blowfish`, `twofish`, `idea`
- Configurable S2K options:
  - Type: `iterated` or `argon2`
  - Iteration count byte (`0-255`) when using `iterated`
  - Hash algorithm selection when using `iterated`

### Hash algorithms (one-way)

- MD5
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA-3
- RIPEMD160

## Main features

- Text encryption/decryption
- File encryption/decryption (`.pgp` flow supported)
- Hash generation
- Multilingual UI (`en`, `ko`, `ja`, `zh`, `es`, `fr`, `de`, `id`, `ar`)

## Crypto format notes

- Encryption/decryption uses PGP-compatible symmetric message format
- No custom `CFGE1` format path in the current implementation

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
