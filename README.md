# gitcellar-crypto

[![CI](https://github.com/gitcellar/gitcellar-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/gitcellar/gitcellar-crypto/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The open-source cryptographic foundation of [GitCellar](https://gitcellar.com) — zero-access encrypted Git hosting.

This repository contains the encryption pipeline's core crates: key generation, identity management, content chunking, and encryption/decryption. We publish this so that security researchers and users can audit exactly how GitCellar protects your code.

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
    |                      XChaCha20-Poly1305 chunk AEAD
    |                      S3-compatible cloud storage (bounded-http
    |                      caps every provider response read)
    |
    Identity keys, .gckey transfer,
    cloud backup with recovery codes
```

## Crates

| Crate | Description |
|-------|-------------|
| **[passkey-core](passkey-core/)** | Cross-platform passwordless identity library. Ed25519/X25519 key generation via Sequoia OpenPGP, BIP39 24-word recovery phrases, challenge-response authentication, multi-user state machine, OS credential storage. |
| **[gitcellar-identity](gitcellar-identity/)** | Thin wrapper that applies GitCellar defaults (app name, path conventions) to passkey-core. |
| **[gitcellar-crypto](gitcellar-crypto/)** | High-level encryption API. Holds the OpenPGP identity and key-grant paths, delegates chunk sealing to vault-core's XChaCha20-Poly1305 engine, handles `.gckey` identity transfer files, and provides cloud backup bundles encrypted with recovery codes. |
| **[vault-core](vault-core/)** | Content-defined chunking (CDC) for deduplication, chunk encryption (XChaCha20-Poly1305 AEAD under a per-repo HKDF-SHA256-derived content key), and S3-compatible cloud storage abstraction (Backblaze B2, Wasabi, AWS S3, MinIO). Also hosts `AesEncryptionEngine` (AES-256-GCM), the passphrase-derived engine used by FFI consumers — that is not the chunk path. |
| **[bounded-http](bounded-http/)** | Size-bounded reads of untrusted HTTP response bodies. The storage provider is treated as an adversary, so no response is buffered past a fixed ceiling; one implementation shared by every provider-facing code path. |

## Algorithms

| Purpose | Algorithm | Implementation |
|---------|-----------|----------------|
| Signing key | Ed25519 | Sequoia OpenPGP |
| Encryption key | X25519 (ECDH) | Sequoia OpenPGP |
| Chunk encryption (your repository's file contents) | XChaCha20-Poly1305 AEAD | `chacha20poly1305` crate — vault-core's `XChaChaChunkEngine`; 24-byte nonce, 16-byte Poly1305 tag |
| Backup bundles, identity bundles, keys at rest | AES-256-GCM | `aes-gcm` crate, HKDF-SHA256-derived keys — this is not the chunk path |
| Content-key derivation | HKDF-SHA256 | `hkdf` crate — per-repo content key, domain-separated `info` string |
| Passphrase key derivation | Argon2id | `argon2` crate (passphrase-derived contexts) |
| Recovery phrases | BIP39 | `bip39` crate (24-word mnemonic, derives encryption keys) |
| Content chunking | Gear-based FastCDC, per-repo keyed Gear table | vault-core (table derived via keyed BLAKE3) |
| Chunk naming | HMAC-SHA256 (keyed) / SHA-256 (unkeyed) | `hmac` / `sha2` crates |
| Hashing | SHA-256 | `sha2` crate |

## How GitCellar Uses This

When a user pushes code to their local GitCellar Forge:

1. **Webhook fires** to the GitCellar Service
2. **vault-core** splits the git bundle into variable-size chunks (~1 MB average) using content-defined chunking, with per-repo keyed boundaries
3. **vault-core** seals each chunk with XChaCha20-Poly1305 under a per-repo content key derived via HKDF-SHA256. The chunk's identity — repository, chunk name, offset, size — is bound into the AEAD as associated data, so a stored chunk only opens under the identity it was sealed with
4. Encrypted chunks are concatenated into larger **pack** blobs, so a stored object's size does not map to a single chunk, and the packs upload to S3-compatible object storage
5. A stream manifest (chunk index) is encrypted and uploaded alongside

The user's private key never leaves their machine, and the storage provider sees only encrypted blobs. This is zero-access encryption — GitCellar cannot decrypt your code.

**What this covers:** your code — the file contents of your repositories. Repository *metadata* that you choose to publish to your Cloud profile — repository names, languages, commit counts, branches — is held server-side in plaintext and is not protected by the encryption described above.

## Building

Requires Rust 1.85 or newer (checked in CI) and platform-specific dependencies for Sequoia OpenPGP:

**Windows:**
```bash
# Uses Windows CNG (Cryptography API: Next Generation) - no extra dependencies
cargo build
```

**macOS/Linux:**
```bash
# Requires the Nettle cryptographic library (and libclang for its bindings)
# Ubuntu/Debian: apt install nettle-dev libclang-dev pkg-config
# macOS: brew install nettle pkg-config
cargo build
```

## Running Tests

```bash
cargo test --workspace
cargo audit            # RustSec advisory check; cargo install cargo-audit
```

CI runs the build and tests on Linux, macOS and Windows, checks the minimum supported Rust
version, and runs `cargo audit` on every push and weekly. `Cargo.lock` is committed so the
dependency set you audit is the one we build.

## Platform Support

Sequoia OpenPGP uses platform-native cryptographic backends:

| Platform | Backend | Notes |
|----------|---------|-------|
| Windows | CNG | Built-in, no extra dependencies |
| macOS | Nettle | Install via Homebrew |
| Linux | Nettle | Install via package manager |

## Scope of This Repository

These five crates are the core of GitCellar's encryption pipeline, not the whole of it. The
network services, the Desktop application and the Git forge are not published. One piece of
the key-management stack — a client for an auditable append-only public-key log — is still being built; it is
gated off in the product and not published here until it ships. What is here is what runs.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Security

If you discover a vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
