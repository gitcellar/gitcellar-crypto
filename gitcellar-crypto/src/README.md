# Crypto Library Source (`src/`)

Sequoia-based encryption library providing identity-bound encryption, cloud backup with recovery codes, and machine-to-machine identity transfer. Re-exports identity management from `gitcellar-identity` (which wraps the reusable `passkey-core` library).

## Purpose & Responsibilities

- **Encryption/decryption** — OpenPGP-based via Sequoia (`encrypt_data`, `decrypt_data`, chunk-level parallel ops)
- **Signing** — Ed25519 detached signatures for protocol authentication
- **Cloud backup** — AES-256-GCM encrypted identity bundles with 24-word BIP-39 recovery codes and optional WebAuthn passkey
- **Identity transfer** — `.gckey` file format for portable identity export/import between machines
- **Multi-user path management** — user-specific paths for identity, keyring, registry, and user data
- **Re-exports** — full `gitcellar-identity` API (generation, loading, multi-user, recovery codes)

## File Index

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 240 | Module hub, multi-user path helpers (`identity_dir`, `user_data_path`, `keyring_dir`, `registry_path`), re-exports from `gitcellar-identity` |
| `encryption.rs` | 447 | `EncryptionEngine` — Sequoia OpenPGP encrypt/decrypt/sign, parallel chunk operations via `tokio::spawn_blocking` |
| `error.rs` | 112 | `CryptoError` enum (20 variants), `Result<T>` alias, conversions from Sequoia and PasskeyError |
| `cloud_backup.rs` | 475 | `CloudBackupBundle` — dual-method recovery (recovery code + passkey PRF), HKDF+AES-256-GCM, JSON serialization |
| `transfer.rs` | 304 | `IdentityBundle` — `.gckey` file format (v2.0/v3.0), export/import with armored PGP wrapper |

**Total:** ~1,578 lines, 28 tests

## Public API & Usage

### Core Types

```rust
// Encryption (this crate)
pub struct EncryptionEngine;          // Wraps Identity + Sequoia StandardPolicy
pub struct CloudBackupBundle;         // Encrypted identity backup for cloud storage
pub struct IdentityBundle;            // .gckey portable identity format

// Re-exported from gitcellar-identity
pub struct Identity;                  // Ed25519/X25519 keypair
pub struct RecoveryCode;              // 24-word BIP-39 mnemonic
pub fn generate_recovery_code() -> Result<RecoveryCode>;
```

### Key Functions

```rust
// Encryption
EncryptionEngine::new(identity) -> Result<Self>
EncryptionEngine::from_default_identity() -> Result<Self>
engine.encrypt_data(data: &[u8]) -> Result<Vec<u8>>
engine.decrypt_data(encrypted: &[u8]) -> Result<Vec<u8>>
engine.encrypt_chunks_parallel(chunks: &[Chunk]) -> Result<Vec<Vec<u8>>>
engine.sign_data(data: &[u8]) -> Result<Vec<u8>>

// Cloud backup
CloudBackupBundle::create_with_recovery_code(identity, key_material) -> Result<Self>
bundle.decrypt_with_recovery_code(key_material) -> Result<Identity>
bundle.to_json() -> Result<String>
CloudBackupBundle::from_json(json: &str) -> Result<Self>

// Transfer
IdentityBundle::export(identity: &Identity) -> Result<String>
IdentityBundle::import(gckey_content: &str) -> Result<Identity>

// Multi-user paths (lib.rs)
pub fn load_active_identity() -> Result<Identity>
pub fn identity_dir() -> PathBuf           // users/{username}/identity/
pub fn user_data_path(subpath: &str) -> PathBuf
pub fn keyring_dir() -> PathBuf
pub fn registry_path() -> PathBuf
```

## Constraints & Business Rules

- **Platform crypto backends**: Windows uses CNG; Unix uses Nettle (Sequoia requirement)
- **`.gckey` files are unencrypted** — "a locked key is an oxymoron." The file IS the secret, stored like an SSH private key
- **Cloud backup supports dual recovery**: recovery code (BIP-39) AND WebAuthn passkey PRF, independently or together
- **Encryption uses HKDF-SHA256 for key derivation** + AES-256-GCM with random salt and nonce per payload
- **`from_default_identity()` loads the active user's identity** — multi-user aware via `get_active_user()`
- **`.gckey` v3.0 is current format**; v2.0 import supported for backwards compatibility; encrypted v2.0 rejected

## Relationships & Dependencies

### Upstream

- **`passkey-core`** — reusable identity library (Ed25519/X25519, BIP-39 recovery)
- **`gitcellar-identity`** — GitCellar-specific defaults (`app_name="gitcellar"`, `prefix="gcm"`)
- **`sequoia-openpgp`** — OpenPGP encryption, decryption, signing
- **`vault-core`** — `Chunk`, `ChunkConfig`, `ChunkEngine` for large file chunking

### Downstream (used by)

- **`gitcellar-service`** — `EncryptionEngine` for webhook-triggered encryption pipeline
- **`gitcellar-desktop`** — identity loading, machine ID derivation, cloud auth signing
- **`gitcellar-cli`** — CLI encryption operations, cloud backup/restore

### Related Docs

- `docs/architecture/encryption/ENCRYPTION_SYSTEM_ARCHITECTURE.md` — core encryption pipeline
- `docs/architecture/encryption/DUAL_RECOVERY_MECHANISM.md` — recovery code + Shamir design
- `docs/architecture/identity/GCKEY_AND_PASSKEY_ARCHITECTURE.md` — `.gckey` design rationale

## Decision Log

**Sequoia over GPG CLI.** Early versions shelled out to `gpg`. Sequoia provides a Rust-native OpenPGP implementation, eliminating the GPG binary dependency and enabling parallel chunk operations via `spawn_blocking`.

**Unencrypted `.gckey` files.** Password-protecting key files creates a false sense of security (weak passwords, forgotten passwords). The file itself is the secret — users store it like an SSH private key (encrypted disk, password manager, physical safe).

**HKDF+AES-256-GCM for cloud backup (not OpenPGP).** Cloud backup needs deterministic decryption from a recovery code, not a certificate. HKDF derives a consistent AES key from the recovery code's key material, which AES-256-GCM uses for authenticated encryption.

**Re-export pattern.** This crate re-exports `gitcellar_identity::*` so consumers only need one dependency (`gitcellar-crypto`) for both identity management and encryption.
