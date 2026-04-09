# gitcellar-crypto

The open-source cryptographic foundation of [GitCellar](https://gitcellar.com) — zero-knowledge encrypted Git hosting.

This repository contains the complete encryption pipeline: key generation, identity management, content chunking, and encryption/decryption. We publish this so that security researchers and users can audit exactly how GitCellar protects your code.

## Architecture

```
passkey-core                   Core identity & authentication primitives
    |                          Ed25519 keys, BIP39 recovery, challenge-response auth
    v
gitcellar-identity             GitCellar-specific identity configuration
    |                          Wraps passkey-core with app defaults
    v
gitcellar-crypto -----> vault-core
    |                      |
    |                      Content-defined chunking (CDC)
    |                      AES-256-GCM & OpenPGP encryption
    |                      S3-compatible cloud storage
    |
    Encryption engine, .gckey transfer,
    cloud backup with recovery codes
```

## Crates

| Crate | Description |
|-------|-------------|
| **[passkey-core](passkey-core/)** | Cross-platform passwordless identity library. Ed25519/X25519 key generation via Sequoia OpenPGP, BIP39 24-word recovery phrases, challenge-response authentication, multi-user state machine, OS credential storage. |
| **[gitcellar-identity](gitcellar-identity/)** | Thin wrapper that applies GitCellar defaults (app name, path conventions) to passkey-core. |
| **[gitcellar-crypto](gitcellar-crypto/)** | High-level encryption API. Encrypts/decrypts data and chunks using Sequoia OpenPGP, handles `.gckey` identity transfer files, and provides cloud backup bundles encrypted with recovery codes. |
| **[vault-core](vault-core/)** | Content-defined chunking (CDC) for deduplication, encryption engines (AES-256-GCM and OpenPGP), and S3-compatible cloud storage abstraction (Backblaze B2, Wasabi, AWS S3, MinIO). |

## Algorithms

| Purpose | Algorithm | Implementation |
|---------|-----------|----------------|
| Signing key | Ed25519 | Sequoia OpenPGP |
| Encryption key | X25519 (ECDH) | Sequoia OpenPGP |
| Symmetric encryption | AES-256-GCM | `aes-gcm` crate (via OpenPGP for data, direct for backup bundles) |
| Key derivation | Argon2id | `argon2` crate (for password-based encryption contexts) |
| Recovery phrases | BIP39 | `bip39` crate (24-word mnemonic, derives encryption keys) |
| Content chunking | CDC (polynomial rolling hash) | Custom implementation in vault-core |
| Hashing | SHA-256 | `sha2` crate |

## How GitCellar Uses This

When a user pushes code to their local GitCellar Forge:

1. **Webhook fires** to the GitCellar Service
2. **vault-core** splits the git bundle into ~1 MB chunks using content-defined chunking
3. **gitcellar-crypto** encrypts each chunk with the repository's OpenPGP key
4. Encrypted chunks upload to Backblaze B2
5. A stream manifest (chunk index) is encrypted and uploaded alongside

The user's private key never leaves their machine. The cloud storage provider sees only encrypted blobs. This is zero-knowledge encryption — GitCellar cannot decrypt your code.

## Building

Requires Rust 1.75+ and platform-specific dependencies for Sequoia OpenPGP:

**Windows:**
```bash
# Uses Windows CNG (Cryptography API: Next Generation) - no extra dependencies
cargo build
```

**macOS/Linux:**
```bash
# Requires Nettle cryptographic library
# Ubuntu/Debian: apt install nettle-dev
# macOS: brew install nettle
cargo build
```

## Running Tests

```bash
cargo test --workspace
```

## Platform Support

Sequoia OpenPGP uses platform-native cryptographic backends:

| Platform | Backend | Notes |
|----------|---------|-------|
| Windows | CNG | Built-in, no extra dependencies |
| macOS | Nettle | Install via Homebrew |
| Linux | Nettle | Install via package manager |

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Security

If you discover a vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
